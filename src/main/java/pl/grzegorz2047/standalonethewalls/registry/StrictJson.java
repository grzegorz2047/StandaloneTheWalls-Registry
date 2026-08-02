package pl.grzegorz2047.standalonethewalls.registry;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/** Strict UTF-8 JSON parser and RFC 8785-compatible encoder for the bounded claim domain. */
final class StrictJson {
    static final int MAX_DEPTH = 8;
    static final int MAX_STRING_CODE_UNITS = 4096;

    sealed interface Value permits ObjectValue, ArrayValue, StringValue, IntegerValue, BooleanValue, NullValue {}

    record ObjectValue(Map<String, Value> values) implements Value {
        ObjectValue {
            values = Collections.unmodifiableMap(new LinkedHashMap<>(Objects.requireNonNull(values, "values")));
        }
    }

    record ArrayValue(List<Value> values) implements Value {
        ArrayValue {
            values = List.copyOf(Objects.requireNonNull(values, "values"));
        }
    }

    record StringValue(String value) implements Value {
        StringValue {
            Objects.requireNonNull(value, "value");
        }
    }

    record IntegerValue(long value) implements Value {}

    record BooleanValue(boolean value) implements Value {}

    enum NullValue implements Value {
        INSTANCE
    }

    private StrictJson() {
        throw new AssertionError("No instances");
    }

    static Value parse(byte[] bytes, int maximumBytes) throws RegistryFailure {
        Objects.requireNonNull(bytes, "bytes");
        if (bytes.length == 0 || bytes.length > maximumBytes) {
            throw new RegistryFailure(
                    RegistryFailure.Code.LIMIT_EXCEEDED, "JSON byte length is outside the configured range");
        }
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        } catch (CharacterCodingException exception) {
            throw new RegistryFailure(
                    RegistryFailure.Code.MALFORMED_UTF8, "JSON is not strict UTF-8", exception);
        }
        Parser parser = new Parser(text);
        Value value = parser.readValue(0);
        if (!parser.atEnd()) {
            throw new RegistryFailure(
                    RegistryFailure.Code.MALFORMED_JSON, "JSON contains trailing data");
        }
        return value;
    }

    static Value parseCanonical(byte[] bytes, int maximumBytes) throws RegistryFailure {
        Value parsed = parse(bytes, maximumBytes);
        byte[] canonical = encode(parsed);
        if (!java.security.MessageDigest.isEqual(bytes, canonical)) {
            throw new RegistryFailure(
                    RegistryFailure.Code.NON_CANONICAL_JSON,
                    "JSON bytes are not canonical RFC 8785 form");
        }
        return parsed;
    }

    static byte[] encode(Value value) throws RegistryFailure {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        write(value, output, 0);
        return output.toByteArray();
    }

    static ObjectValue object(Map<String, Value> values) {
        return new ObjectValue(values);
    }

    static ArrayValue array(List<Value> values) {
        return new ArrayValue(values);
    }

    static StringValue string(String value) {
        return new StringValue(value);
    }

    static IntegerValue integer(long value) {
        return new IntegerValue(value);
    }

    static BooleanValue bool(boolean value) {
        return new BooleanValue(value);
    }

    static NullValue nil() {
        return NullValue.INSTANCE;
    }

    static ObjectValue requireObject(Value value, String part) throws RegistryFailure {
        if (value instanceof ObjectValue object) {
            return object;
        }
        throw malformed(part + " must be an object");
    }

    static ArrayValue requireArray(Value value, String part) throws RegistryFailure {
        if (value instanceof ArrayValue array) {
            return array;
        }
        throw malformed(part + " must be an array");
    }

    static String requireString(Value value, String part) throws RegistryFailure {
        if (value instanceof StringValue string) {
            return string.value();
        }
        throw malformed(part + " must be a string");
    }

    static String requireNullableString(Value value, String part) throws RegistryFailure {
        if (value == NullValue.INSTANCE) {
            return null;
        }
        return requireString(value, part);
    }

    static long requireInteger(Value value, String part) throws RegistryFailure {
        if (value instanceof IntegerValue integer) {
            return integer.value();
        }
        throw malformed(part + " must be an integer");
    }

    private static void write(Value value, ByteArrayOutputStream output, int depth)
            throws RegistryFailure {
        if (depth > MAX_DEPTH) {
            throw new RegistryFailure(
                    RegistryFailure.Code.LIMIT_EXCEEDED, "JSON nesting depth exceeds the limit");
        }
        if (value instanceof ObjectValue object) {
            output.write('{');
            boolean first = true;
            for (Map.Entry<String, Value> entry : new TreeMap<>(object.values()).entrySet()) {
                if (!first) {
                    output.write(',');
                }
                first = false;
                writeString(entry.getKey(), output);
                output.write(':');
                write(entry.getValue(), output, depth + 1);
            }
            output.write('}');
        } else if (value instanceof ArrayValue array) {
            output.write('[');
            boolean first = true;
            for (Value element : array.values()) {
                if (!first) {
                    output.write(',');
                }
                first = false;
                write(element, output, depth + 1);
            }
            output.write(']');
        } else if (value instanceof StringValue string) {
            writeString(string.value(), output);
        } else if (value instanceof IntegerValue integer) {
            byte[] encoded = Long.toString(integer.value()).getBytes(StandardCharsets.US_ASCII);
            output.writeBytes(encoded);
        } else if (value instanceof BooleanValue bool) {
            output.writeBytes((bool.value() ? "true" : "false").getBytes(StandardCharsets.US_ASCII));
        } else if (value == NullValue.INSTANCE) {
            output.writeBytes("null".getBytes(StandardCharsets.US_ASCII));
        } else {
            throw malformed("unsupported JSON value");
        }
    }

    private static void writeString(String value, ByteArrayOutputStream output)
            throws RegistryFailure {
        validateUnicode(value);
        output.write('"');
        StringBuilder chunk = new StringBuilder();
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            String escape = switch (character) {
                case '"' -> "\\\"";
                case '\\' -> "\\\\";
                case '\b' -> "\\b";
                case '\t' -> "\\t";
                case '\n' -> "\\n";
                case '\f' -> "\\f";
                case '\r' -> "\\r";
                default -> null;
            };
            if (escape != null || character < 0x20) {
                flushChunk(chunk, output);
                if (escape != null) {
                    output.writeBytes(escape.getBytes(StandardCharsets.US_ASCII));
                } else {
                    String encoded = String.format(java.util.Locale.ROOT, "\\u%04x", (int) character);
                    output.writeBytes(encoded.getBytes(StandardCharsets.US_ASCII));
                }
            } else {
                chunk.append(character);
            }
        }
        flushChunk(chunk, output);
        output.write('"');
    }

    private static void flushChunk(StringBuilder chunk, ByteArrayOutputStream output) {
        if (!chunk.isEmpty()) {
            output.writeBytes(chunk.toString().getBytes(StandardCharsets.UTF_8));
            chunk.setLength(0);
        }
    }

    private static void validateUnicode(String value) throws RegistryFailure {
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (Character.isHighSurrogate(character)) {
                if (index + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(index + 1))) {
                    throw malformed("JSON string contains an unpaired surrogate");
                }
                index++;
            } else if (Character.isLowSurrogate(character)) {
                throw malformed("JSON string contains an unpaired surrogate");
            }
        }
    }

    private static RegistryFailure malformed(String message) {
        return new RegistryFailure(RegistryFailure.Code.MALFORMED_JSON, message);
    }

    private static final class Parser {
        private final String text;
        private int position;

        private Parser(String text) {
            this.text = text;
        }

        private boolean atEnd() {
            return position == text.length();
        }

        private Value readValue(int depth) throws RegistryFailure {
            if (depth > MAX_DEPTH) {
                throw new RegistryFailure(
                        RegistryFailure.Code.LIMIT_EXCEEDED, "JSON nesting depth exceeds the limit");
            }
            if (atEnd()) {
                throw malformed("unexpected end of JSON");
            }
            return switch (text.charAt(position)) {
                case '{' -> readObject(depth + 1);
                case '[' -> readArray(depth + 1);
                case '"' -> new StringValue(readString());
                case 't' -> readLiteral("true", new BooleanValue(true));
                case 'f' -> readLiteral("false", new BooleanValue(false));
                case 'n' -> readLiteral("null", NullValue.INSTANCE);
                default -> readNumber();
            };
        }

        private ObjectValue readObject(int depth) throws RegistryFailure {
            position++;
            Map<String, Value> values = new LinkedHashMap<>();
            if (consume('}')) {
                return new ObjectValue(values);
            }
            while (true) {
                String name = readString();
                if (values.containsKey(name)) {
                    throw new RegistryFailure(
                            RegistryFailure.Code.DUPLICATE_FIELD, "JSON object repeats a field");
                }
                require(':');
                values.put(name, readValue(depth));
                if (consume('}')) {
                    return new ObjectValue(values);
                }
                require(',');
            }
        }

        private ArrayValue readArray(int depth) throws RegistryFailure {
            position++;
            List<Value> values = new ArrayList<>();
            if (consume(']')) {
                return new ArrayValue(values);
            }
            while (true) {
                values.add(readValue(depth));
                if (consume(']')) {
                    return new ArrayValue(values);
                }
                require(',');
            }
        }

        private String readString() throws RegistryFailure {
            require('"');
            StringBuilder value = new StringBuilder();
            while (!atEnd()) {
                char character = text.charAt(position++);
                if (character == '"') {
                    if (value.length() > MAX_STRING_CODE_UNITS) {
                        throw new RegistryFailure(
                                RegistryFailure.Code.LIMIT_EXCEEDED,
                                "JSON string exceeds the safe length");
                    }
                    validateUnicode(value.toString());
                    return value.toString();
                }
                if (character == '\\') {
                    if (atEnd()) {
                        throw malformed("unterminated JSON escape");
                    }
                    char escape = text.charAt(position++);
                    switch (escape) {
                        case '"', '\\', '/' -> value.append(escape);
                        case 'b' -> value.append('\b');
                        case 'f' -> value.append('\f');
                        case 'n' -> value.append('\n');
                        case 'r' -> value.append('\r');
                        case 't' -> value.append('\t');
                        case 'u' -> value.append(readUnicodeEscape());
                        default -> throw malformed("invalid JSON escape");
                    }
                } else {
                    if (character < 0x20) {
                        throw malformed("JSON string contains an unescaped control character");
                    }
                    value.append(character);
                }
            }
            throw malformed("unterminated JSON string");
        }

        private char readUnicodeEscape() throws RegistryFailure {
            if (position + 4 > text.length()) {
                throw malformed("truncated JSON Unicode escape");
            }
            int value = 0;
            for (int index = 0; index < 4; index++) {
                int digit = Character.digit(text.charAt(position++), 16);
                if (digit < 0) {
                    throw malformed("invalid JSON Unicode escape");
                }
                value = (value << 4) | digit;
            }
            return (char) value;
        }

        private Value readNumber() throws RegistryFailure {
            int start = position;
            if (consume('-')) {
                if (atEnd()) {
                    throw malformed("truncated JSON number");
                }
            }
            if (consume('0')) {
                if (!atEnd() && Character.isDigit(text.charAt(position))) {
                    throw malformed("JSON integer contains a leading zero");
                }
            } else {
                if (atEnd() || text.charAt(position) < '1' || text.charAt(position) > '9') {
                    throw malformed("JSON value is invalid");
                }
                while (!atEnd() && Character.isDigit(text.charAt(position))) {
                    position++;
                }
            }
            if (!atEnd()) {
                char suffix = text.charAt(position);
                if (suffix == '.' || suffix == 'e' || suffix == 'E') {
                    throw malformed("fractional JSON numbers are not allowed in this schema");
                }
            }
            String encoded = text.substring(start, position);
            if (encoded.equals("-0")) {
                throw malformed("negative zero is not canonical");
            }
            try {
                return new IntegerValue(Long.parseLong(encoded));
            } catch (NumberFormatException exception) {
                throw new RegistryFailure(
                        RegistryFailure.Code.MALFORMED_JSON,
                        "JSON integer is outside the signed 64-bit range",
                        exception);
            }
        }

        private Value readLiteral(String literal, Value value) throws RegistryFailure {
            if (!text.startsWith(literal, position)) {
                throw malformed("invalid JSON literal");
            }
            position += literal.length();
            return value;
        }

        private boolean consume(char expected) {
            if (!atEnd() && text.charAt(position) == expected) {
                position++;
                return true;
            }
            return false;
        }

        private void require(char expected) throws RegistryFailure {
            if (!consume(expected)) {
                throw malformed("JSON syntax is invalid");
            }
        }
    }
}
