package pl.grzegorz2047.standalonethewalls.registry;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Strict claim loading, signature verification and deterministic history resolution. */
final class ClaimPipeline {
    static final int CLAIM_SCHEMA_VERSION = 1;
    static final int OPERATION_VERSION = 1;
    static final int MAXIMUM_CLAIM_BYTES = 65_536;
    static final int MAXIMUM_CLAIM_FILES = 10_000;
    static final int MAXIMUM_OPERATIONS_PER_HANDLE = 128;

    enum Status {
        ACTIVE,
        REVOKED
    }

    record ResolvedClaim(
            String handle,
            String displayName,
            String playerId,
            String publicKeyBase64,
            Status status) {}

    record Resolution(List<ResolvedClaim> claims) {
        Resolution {
            claims = List.copyOf(claims);
        }
    }

    private ClaimPipeline() {
        throw new AssertionError("No instances");
    }

    static Resolution loadAndResolve(Path claimsRoot) throws RegistryFailure {
        return resolve(loadFiles(claimsRoot));
    }

    static Resolution resolve(List<ClaimFile> files) throws RegistryFailure {
        if (files.size() > MAXIMUM_CLAIM_FILES) {
            throw new RegistryFailure(
                    RegistryFailure.Code.LIMIT_EXCEEDED, "claim count exceeds the safe limit");
        }
        List<ClaimFile> ordered = new ArrayList<>(files);
        ordered.sort(Comparator.comparing(ClaimFile::portablePath));
        Set<String> handles = new HashSet<>();
        Map<String, String> skeletonOwners = new HashMap<>();
        List<ResolvedClaim> resolved = new ArrayList<>();
        for (ClaimFile file : ordered) {
            if (!handles.add(file.handle())) {
                throw new RegistryFailure(
                        RegistryFailure.Code.INVALID_OPERATION,
                        "more than one claim history targets the same canonical handle");
            }
            String skeleton = HandlePolicy.skeleton(file.handle());
            String previous = skeletonOwners.putIfAbsent(skeleton, file.handle());
            if (previous != null && !previous.equals(file.handle())) {
                throw new RegistryFailure(
                        RegistryFailure.Code.CONFUSABLE_COLLISION,
                        "canonical handles collide under Unicode policy version 1");
            }
            resolved.add(resolveHistory(file));
        }
        resolved.sort(Comparator.comparing(ResolvedClaim::handle));
        return new Resolution(resolved);
    }

    static List<ClaimFile> loadFiles(Path claimsRoot) throws RegistryFailure {
        Objects.requireNonNull(claimsRoot, "claimsRoot");
        if (!Files.isDirectory(claimsRoot, LinkOption.NOFOLLOW_LINKS)) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_PATH, "claims root must be a real directory");
        }
        List<Path> paths;
        try (var stream = Files.walk(claimsRoot)) {
            paths = stream.filter(path -> !path.equals(claimsRoot)).toList();
        } catch (IOException exception) {
            throw new RegistryFailure(
                    RegistryFailure.Code.IO, "claim tree could not be enumerated", exception);
        }
        List<ClaimFile> claims = new ArrayList<>();
        for (Path path : paths) {
            if (Files.isSymbolicLink(path)) {
                throw new RegistryFailure(
                        RegistryFailure.Code.INVALID_PATH, "symbolic links are forbidden in claims");
            }
            if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                continue;
            }
            if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                throw new RegistryFailure(
                        RegistryFailure.Code.INVALID_PATH, "claim paths must be regular files");
            }
            if (!path.getFileName().toString().endsWith(".json")) {
                throw new RegistryFailure(
                        RegistryFailure.Code.INVALID_PATH, "claims tree contains a non-JSON file");
            }
            claims.add(parseFile(claimsRoot, path));
            if (claims.size() > MAXIMUM_CLAIM_FILES) {
                throw new RegistryFailure(
                        RegistryFailure.Code.LIMIT_EXCEEDED, "claim count exceeds the safe limit");
            }
        }
        return List.copyOf(claims);
    }

    static ClaimFile parseFile(Path claimsRoot, Path file) throws RegistryFailure {
        byte[] bytes;
        try {
            long size = Files.size(file);
            if (size <= 0 || size > MAXIMUM_CLAIM_BYTES) {
                throw new RegistryFailure(
                        RegistryFailure.Code.LIMIT_EXCEEDED,
                        "claim file byte length is outside the safe range");
            }
            bytes = Files.readAllBytes(file);
        } catch (RegistryFailure failure) {
            throw failure;
        } catch (IOException exception) {
            throw new RegistryFailure(RegistryFailure.Code.IO, "claim file could not be read", exception);
        }
        StrictJson.ObjectValue root = StrictJson.requireObject(
                StrictJson.parseCanonical(bytes, MAXIMUM_CLAIM_BYTES), "claim");
        requireFields(root, Set.of("handle", "operations", "policyVersion", "schema"), "claim");
        String handle = StrictJson.requireString(required(root, "handle"), "handle");
        HandlePolicy.validateHandle(handle);
        long schema = StrictJson.requireInteger(required(root, "schema"), "schema");
        long policyVersion = StrictJson.requireInteger(required(root, "policyVersion"), "policyVersion");
        if (schema != CLAIM_SCHEMA_VERSION || policyVersion != HandlePolicy.POLICY_VERSION) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_OPERATION,
                    "claim schema or policy version is unsupported");
        }
        validatePath(claimsRoot, file, handle);
        StrictJson.ArrayValue operationValues = StrictJson.requireArray(
                required(root, "operations"), "operations");
        if (operationValues.values().isEmpty()
                || operationValues.values().size() > MAXIMUM_OPERATIONS_PER_HANDLE) {
            throw new RegistryFailure(
                    RegistryFailure.Code.LIMIT_EXCEEDED,
                    "claim operation count is outside the safe range");
        }
        List<Operation> operations = new ArrayList<>();
        for (StrictJson.Value value : operationValues.values()) {
            operations.add(parseOperation(handle, root, StrictJson.requireObject(value, "operation")));
        }
        Path relative = claimsRoot.toAbsolutePath().normalize()
                .relativize(file.toAbsolutePath().normalize());
        return new ClaimFile(
                relative.toString().replace(file.getFileSystem().getSeparator(), "/"),
                handle,
                List.copyOf(operations));
    }

    static byte[] transcript(
            String handle, StrictJson.ObjectValue root, StrictJson.ObjectValue operation)
            throws RegistryFailure {
        Map<String, StrictJson.Value> stripped = new LinkedHashMap<>(operation.values());
        stripped.remove("signature");
        stripped.remove("oldSignature");
        stripped.remove("newSignature");
        Map<String, StrictJson.Value> transcript = new LinkedHashMap<>();
        transcript.put("handle", StrictJson.string(handle));
        transcript.put("operation", StrictJson.object(stripped));
        transcript.put("policyVersion", required(root, "policyVersion"));
        transcript.put("schema", required(root, "schema"));
        return StrictJson.encode(StrictJson.object(transcript));
    }

    private static Operation parseOperation(
            String handle, StrictJson.ObjectValue root, StrictJson.ObjectValue operation)
            throws RegistryFailure {
        String typeText = StrictJson.requireString(required(operation, "operation"), "operation");
        OperationType type;
        try {
            type = OperationType.valueOf(typeText);
        } catch (IllegalArgumentException exception) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_OPERATION, "operation type is unsupported", exception);
        }
        Set<String> expected = switch (type) {
            case CLAIM -> Set.of(
                    "displayName",
                    "operation",
                    "playerId",
                    "publicKey",
                    "sequence",
                    "signature",
                    "version");
            case ROTATE -> Set.of(
                    "displayName",
                    "newPlayerId",
                    "newPublicKey",
                    "newSignature",
                    "oldSignature",
                    "operation",
                    "previousPlayerId",
                    "sequence",
                    "version");
            case SET_DISPLAY_NAME -> Set.of(
                    "displayName",
                    "operation",
                    "playerId",
                    "sequence",
                    "signature",
                    "version");
            case REVOKE -> Set.of(
                    "operation", "playerId", "sequence", "signature", "version");
        };
        requireFields(operation, expected, "operation");
        long version = StrictJson.requireInteger(required(operation, "version"), "version");
        long sequence = StrictJson.requireInteger(required(operation, "sequence"), "sequence");
        if (version != OPERATION_VERSION || sequence <= 0) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_SEQUENCE,
                    "operation version or sequence is invalid");
        }
        byte[] transcript = transcript(handle, root, operation);
        return switch (type) {
            case CLAIM -> new ClaimOperation(
                    sequence,
                    nullableDisplayName(operation),
                    text(operation, "playerId"),
                    text(operation, "publicKey"),
                    text(operation, "signature"),
                    transcript);
            case ROTATE -> new RotateOperation(
                    sequence,
                    nullableDisplayName(operation),
                    text(operation, "previousPlayerId"),
                    text(operation, "newPlayerId"),
                    text(operation, "newPublicKey"),
                    text(operation, "oldSignature"),
                    text(operation, "newSignature"),
                    transcript);
            case SET_DISPLAY_NAME -> new SetDisplayNameOperation(
                    sequence,
                    nullableDisplayName(operation),
                    text(operation, "playerId"),
                    text(operation, "signature"),
                    transcript);
            case REVOKE -> new RevokeOperation(
                    sequence,
                    text(operation, "playerId"),
                    text(operation, "signature"),
                    transcript);
        };
    }

    private static ResolvedClaim resolveHistory(ClaimFile file) throws RegistryFailure {
        State state = null;
        long expectedSequence = 1;
        for (Operation operation : file.operations()) {
            if (operation.sequence() != expectedSequence) {
                throw new RegistryFailure(
                        RegistryFailure.Code.INVALID_SEQUENCE,
                        "claim history contains a gap, duplicate or reordering");
            }
            if (state != null && state.status == Status.REVOKED) {
                throw new RegistryFailure(
                        RegistryFailure.Code.INVALID_OPERATION,
                        "revoked handles cannot be reactivated or modified");
            }
            if (operation instanceof ClaimOperation claim) {
                if (state != null || expectedSequence != 1) {
                    throw new RegistryFailure(
                            RegistryFailure.Code.INVALID_OPERATION,
                            "CLAIM is legal only as the first operation");
                }
                PublicKey key = validateKeyAndPlayer(claim.publicKey(), claim.playerId());
                HandlePolicy.validateDisplayName(claim.displayName());
                requireSignature(key, claim.transcript(), claim.signature());
                state = new State(claim.displayName(), claim.playerId(), claim.publicKey(), key, Status.ACTIVE);
            } else if (operation instanceof RotateOperation rotate) {
                state = requireActive(state);
                if (!state.playerId.equals(rotate.previousPlayerId())) {
                    throw new RegistryFailure(
                            RegistryFailure.Code.INVALID_OPERATION,
                            "rotation previousPlayerId does not match the active key");
                }
                PublicKey newKey = validateKeyAndPlayer(rotate.newPublicKey(), rotate.newPlayerId());
                if (state.playerId.equals(rotate.newPlayerId())) {
                    throw new RegistryFailure(
                            RegistryFailure.Code.INVALID_OPERATION,
                            "rotation must replace the active player key");
                }
                HandlePolicy.validateDisplayName(rotate.displayName());
                requireSignature(state.publicKey, rotate.transcript(), rotate.oldSignature());
                requireSignature(newKey, rotate.transcript(), rotate.newSignature());
                state = new State(
                        rotate.displayName(),
                        rotate.newPlayerId(),
                        rotate.newPublicKey(),
                        newKey,
                        Status.ACTIVE);
            } else if (operation instanceof SetDisplayNameOperation display) {
                state = requireActive(state);
                if (!state.playerId.equals(display.playerId())) {
                    throw new RegistryFailure(
                            RegistryFailure.Code.INVALID_OPERATION,
                            "display-name operation does not target the active playerId");
                }
                HandlePolicy.validateDisplayName(display.displayName());
                requireSignature(state.publicKey, display.transcript(), display.signature());
                state = new State(
                        display.displayName(),
                        state.playerId,
                        state.publicKeyBase64,
                        state.publicKey,
                        Status.ACTIVE);
            } else if (operation instanceof RevokeOperation revoke) {
                state = requireActive(state);
                if (!state.playerId.equals(revoke.playerId())) {
                    throw new RegistryFailure(
                            RegistryFailure.Code.INVALID_OPERATION,
                            "revoke does not target the active playerId");
                }
                requireSignature(state.publicKey, revoke.transcript(), revoke.signature());
                state = new State(
                        state.displayName,
                        state.playerId,
                        state.publicKeyBase64,
                        state.publicKey,
                        Status.REVOKED);
            }
            expectedSequence++;
        }
        if (state == null) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_OPERATION, "claim history resolves to no state");
        }
        return new ResolvedClaim(
                file.handle(),
                state.displayName,
                state.playerId,
                state.publicKeyBase64,
                state.status);
    }

    private static State requireActive(State state) throws RegistryFailure {
        if (state == null || state.status != Status.ACTIVE) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_OPERATION,
                    "operation requires an active preceding claim");
        }
        return state;
    }

    private static PublicKey validateKeyAndPlayer(String publicKey, String playerId)
            throws RegistryFailure {
        PublicKey key = RegistryCrypto.decodeEd25519Spki(publicKey);
        if (!RegistryCrypto.canonicalSpkiBase64(key).equals(publicKey)) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_PUBLIC_KEY,
                    "claim public key is not canonical Base64 SPKI");
        }
        if (!RegistryCrypto.playerId(key).equals(playerId)) {
            throw new RegistryFailure(
                    RegistryFailure.Code.PLAYER_ID_MISMATCH,
                    "declared playerId does not match the public key");
        }
        return key;
    }

    private static void requireSignature(PublicKey key, byte[] transcript, String signature)
            throws RegistryFailure {
        if (!RegistryCrypto.verify(key, transcript, RegistryCrypto.decodeSignature(signature))) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_SIGNATURE,
                    "operation signature is invalid for the canonical transcript");
        }
    }

    private static void validatePath(Path root, Path file, String handle) throws RegistryFailure {
        Path relative = root.toAbsolutePath().normalize()
                .relativize(file.toAbsolutePath().normalize());
        if (relative.getNameCount() != 2) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_PATH,
                    "claim path must be claims/<prefix>/<canonical-handle>.json");
        }
        String prefix = relative.getName(0).toString();
        String filename = relative.getName(1).toString();
        String expectedPrefix = RegistryCrypto.pathPrefix(handle);
        if (!prefix.equals(expectedPrefix)
                || !filename.equals(handle + ".json")
                || !prefix.equals(prefix.toLowerCase(Locale.ROOT))) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_PATH,
                    "claim path does not match its handle or deterministic prefix");
        }
    }

    private static StrictJson.Value required(StrictJson.ObjectValue object, String name)
            throws RegistryFailure {
        StrictJson.Value value = object.values().get(name);
        if (value == null) {
            throw new RegistryFailure(
                    RegistryFailure.Code.MISSING_FIELD, "required JSON field is missing");
        }
        return value;
    }

    private static String text(StrictJson.ObjectValue object, String name) throws RegistryFailure {
        return StrictJson.requireString(required(object, name), name);
    }

    private static String nullableDisplayName(StrictJson.ObjectValue operation)
            throws RegistryFailure {
        return StrictJson.requireNullableString(required(operation, "displayName"), "displayName");
    }

    private static void requireFields(
            StrictJson.ObjectValue object, Set<String> expected, String part)
            throws RegistryFailure {
        for (String actual : object.values().keySet()) {
            if (!expected.contains(actual)) {
                throw new RegistryFailure(
                        RegistryFailure.Code.UNKNOWN_FIELD, part + " contains an unknown field");
            }
        }
        if (!object.values().keySet().containsAll(expected)) {
            throw new RegistryFailure(
                    RegistryFailure.Code.MISSING_FIELD, part + " is missing a required field");
        }
    }

    record ClaimFile(String portablePath, String handle, List<Operation> operations) {
        ClaimFile {
            operations = List.copyOf(operations);
        }
    }

    private enum OperationType {
        CLAIM,
        ROTATE,
        SET_DISPLAY_NAME,
        REVOKE
    }

    sealed interface Operation
            permits ClaimOperation, RotateOperation, SetDisplayNameOperation, RevokeOperation {
        long sequence();

        byte[] transcript();
    }

    record ClaimOperation(
            long sequence,
            String displayName,
            String playerId,
            String publicKey,
            String signature,
            byte[] transcript)
            implements Operation {
        ClaimOperation {
            transcript = transcript.clone();
        }

        @Override
        public byte[] transcript() {
            return transcript.clone();
        }
    }

    record RotateOperation(
            long sequence,
            String displayName,
            String previousPlayerId,
            String newPlayerId,
            String newPublicKey,
            String oldSignature,
            String newSignature,
            byte[] transcript)
            implements Operation {
        RotateOperation {
            transcript = transcript.clone();
        }

        @Override
        public byte[] transcript() {
            return transcript.clone();
        }
    }

    record SetDisplayNameOperation(
            long sequence,
            String displayName,
            String playerId,
            String signature,
            byte[] transcript)
            implements Operation {
        SetDisplayNameOperation {
            transcript = transcript.clone();
        }

        @Override
        public byte[] transcript() {
            return transcript.clone();
        }
    }

    record RevokeOperation(
            long sequence, String playerId, String signature, byte[] transcript)
            implements Operation {
        RevokeOperation {
            transcript = transcript.clone();
        }

        @Override
        public byte[] transcript() {
            return transcript.clone();
        }
    }

    private static final class State {
        private final String displayName;
        private final String playerId;
        private final String publicKeyBase64;
        private final PublicKey publicKey;
        private final Status status;

        private State(
                String displayName,
                String playerId,
                String publicKeyBase64,
                PublicKey publicKey,
                Status status) {
            this.displayName = displayName;
            this.playerId = playerId;
            this.publicKeyBase64 = publicKeyBase64;
            this.publicKey = publicKey;
            this.status = status;
        }
    }
}
