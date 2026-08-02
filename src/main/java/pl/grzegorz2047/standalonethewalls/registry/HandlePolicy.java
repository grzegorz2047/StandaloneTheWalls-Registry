package pl.grzegorz2047.standalonethewalls.registry;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** Versioned canonical-handle, display-name, reserved-name and UTS #39 policy. */
final class HandlePolicy {
    static final int POLICY_VERSION = 1;
    static final String UNICODE_VERSION = "17.0.0";
    static final String CONFUSABLES_SOURCE_SHA256 =
            "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a";
    private static final Pattern HANDLE = Pattern.compile("[a-z0-9_]{3,24}");
    private static final Set<String> RESERVED = Set.of(
            "admin",
            "administrator",
            "moderator",
            "mod",
            "owner",
            "root",
            "server",
            "system",
            "support",
            "sunderfront",
            "standalonethewalls",
            "thewalls");
    private static final Map<Integer, String> CONFUSABLES = loadConfusables();

    private HandlePolicy() {
        throw new AssertionError("No instances");
    }

    static void validateHandle(String handle) throws RegistryFailure {
        if (handle == null || !HANDLE.matcher(handle).matches()) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_HANDLE,
                    "canonical handle must match [a-z0-9_]{3,24}");
        }
        if (RESERVED.contains(handle)) {
            throw new RegistryFailure(
                    RegistryFailure.Code.RESERVED_HANDLE,
                    "canonical handle is reserved by policy version 1");
        }
    }

    static void validateDisplayName(String displayName) throws RegistryFailure {
        if (displayName == null) {
            return;
        }
        if (!displayName.equals(Normalizer.normalize(displayName, Normalizer.Form.NFC))) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_DISPLAY_NAME,
                    "display name must already be NFC-normalized");
        }
        if (displayName.isBlank() || !displayName.equals(displayName.strip())) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_DISPLAY_NAME,
                    "display name cannot be blank or have edge whitespace");
        }
        if (displayName.codePointCount(0, displayName.length()) > 32
                || displayName.getBytes(StandardCharsets.UTF_8).length > 128) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_DISPLAY_NAME,
                    "display name exceeds the bounded length");
        }
        for (int index = 0; index < displayName.length(); ) {
            int codePoint = displayName.codePointAt(index);
            index += Character.charCount(codePoint);
            int type = Character.getType(codePoint);
            if (type == Character.CONTROL
                    || type == Character.FORMAT
                    || type == Character.PRIVATE_USE
                    || type == Character.SURROGATE
                    || type == Character.UNASSIGNED
                    || type == Character.LINE_SEPARATOR
                    || type == Character.PARAGRAPH_SEPARATOR) {
                throw new RegistryFailure(
                        RegistryFailure.Code.INVALID_DISPLAY_NAME,
                        "display name contains a disallowed Unicode code point");
            }
        }
    }

    static String skeleton(String handle) throws RegistryFailure {
        validateHandle(handle);
        String normalized = Normalizer.normalize(handle, Normalizer.Form.NFD);
        StringBuilder mapped = new StringBuilder();
        normalized.codePoints()
                .forEach(codePoint -> mapped.append(CONFUSABLES.getOrDefault(codePoint, new String(Character.toChars(codePoint)))));
        return Normalizer.normalize(mapped.toString(), Normalizer.Form.NFD)
                .toLowerCase(Locale.ROOT);
    }

    static boolean isReserved(String handle) {
        return RESERVED.contains(handle);
    }

    private static Map<Integer, String> loadConfusables() {
        InputStream stream = HandlePolicy.class.getResourceAsStream(
                "/unicode/confusables-ascii-v17.0.0.txt");
        if (stream == null) {
            throw new ExceptionInInitializerError("missing pinned Unicode confusables data");
        }
        Map<Integer, String> mappings = new HashMap<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            for (String line = reader.readLine(); line != null; line = reader.readLine()) {
                String content = line.split("#", 2)[0].trim();
                if (content.isEmpty()) {
                    continue;
                }
                String[] parts = content.split(";");
                int source = Integer.parseInt(parts[0].trim(), 16);
                StringBuilder target = new StringBuilder();
                for (String encoded : parts[1].trim().split("\\s+")) {
                    target.appendCodePoint(Integer.parseInt(encoded, 16));
                }
                mappings.put(source, target.toString());
            }
        } catch (IOException | RuntimeException exception) {
            throw new ExceptionInInitializerError(exception);
        }
        return Map.copyOf(mappings);
    }
}
