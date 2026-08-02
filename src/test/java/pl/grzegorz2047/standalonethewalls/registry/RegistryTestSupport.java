package pl.grzegorz2047.standalonethewalls.registry;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class RegistryTestSupport {
    private static final String VECTOR_KEY =
            "MCowBQYDK2VwAyEAoBGdJyYRGPquhsJXoEoTOOticDHR4bM2z/5DScGCHPU=";
    private static final String VECTOR_PLAYER =
            "sf1_ne2243wbcs3fox5evlg23khripu53paxtss2ckqxnycbtqgks7ua";
    private static final String VECTOR_ROOT =
            "sfr1_ne2243wbcs3fox5evlg23khripu53paxtss2ckqxnycbtqgks7ua";
    private static final String VECTOR_JSON =
            "{\"entries\":[{\"handle\":\"player_one\",\"playerId\":\""
                    + VECTOR_PLAYER
                    + "\",\"publicKey\":\""
                    + VECTOR_KEY
                    + "\",\"status\":\"ACTIVE\"}],\"generatedAt\":\"2026-08-02T00:00:00Z\",\"rootKeyId\":\""
                    + VECTOR_ROOT
                    + "\",\"schema\":1,\"sequence\":7}";

    private RegistryTestSupport() {
        throw new AssertionError("No instances");
    }

    static void runAll() throws Exception {
        validClaimAndSignatureFailures();
        strictJsonAndSchemaFailures();
        pathReservedAndConfusablePolicy();
        rotationAndRevokeLifecycle();
        deterministicResolutionAndSnapshot();
        publicConsumerVector();
        detachedArtifactFailures();
        missingRootSecretFailsClosed();
    }

    static void validClaimAndSignatureFailures() throws Exception {
        KeyPair player = keyPair();
        Path root = Files.createTempDirectory("registry-valid-");
        writeHistory(root, "valid_user", List.of(claim("valid_user", player, "Valid User")));
        ClaimPipeline.Resolution resolution = ClaimPipeline.loadAndResolve(root);
        equal(1, resolution.claims().size(), "valid claim count");
        equal(RegistryCrypto.playerId(player.getPublic()), resolution.claims().getFirst().playerId(), "player ID");

        expectCode(
                RegistryFailure.Code.INVALID_SIGNATURE,
                () -> {
                    Path invalid = Files.createTempDirectory("registry-bad-sig-");
                    StrictJson.ObjectValue operation = claim("bad_signature", player, null);
                    Map<String, StrictJson.Value> changed = new LinkedHashMap<>(operation.values());
                    changed.put("signature", StrictJson.string(Base64.getEncoder().encodeToString(new byte[64])));
                    writeHistory(invalid, "bad_signature", List.of(StrictJson.object(changed)));
                    ClaimPipeline.loadAndResolve(invalid);
                });

        KeyPair other = keyPair();
        expectCode(
                RegistryFailure.Code.INVALID_SIGNATURE,
                () -> {
                    Path invalid = Files.createTempDirectory("registry-other-key-");
                    StrictJson.ObjectValue operation = claim("other_key", player, null);
                    Map<String, StrictJson.Value> changed = new LinkedHashMap<>(operation.values());
                    byte[] transcript = transcript("other_key", StrictJson.object(withoutSignatures(changed)));
                    changed.put("signature", StrictJson.string(RegistryCrypto.encodeBase64(
                            RegistryCrypto.sign(other.getPrivate(), transcript))));
                    writeHistory(invalid, "other_key", List.of(StrictJson.object(changed)));
                    ClaimPipeline.loadAndResolve(invalid);
                });

        expectCode(
                RegistryFailure.Code.PLAYER_ID_MISMATCH,
                () -> {
                    Path invalid = Files.createTempDirectory("registry-player-id-");
                    StrictJson.ObjectValue operation = claim("mismatch_id", player, null);
                    Map<String, StrictJson.Value> changed = new LinkedHashMap<>(operation.values());
                    changed.put("playerId", StrictJson.string(VECTOR_PLAYER));
                    byte[] transcript = transcript("mismatch_id", StrictJson.object(withoutSignatures(changed)));
                    changed.put("signature", StrictJson.string(RegistryCrypto.encodeBase64(
                            RegistryCrypto.sign(player.getPrivate(), transcript))));
                    writeHistory(invalid, "mismatch_id", List.of(StrictJson.object(changed)));
                    ClaimPipeline.loadAndResolve(invalid);
                });

        expectCode(
                RegistryFailure.Code.INVALID_PUBLIC_KEY,
                () -> {
                    Path invalid = Files.createTempDirectory("registry-invalid-key-");
                    Map<String, StrictJson.Value> operation = new LinkedHashMap<>(claim("invalid_key", player, null).values());
                    operation.put("publicKey", StrictJson.string(Base64.getEncoder().encodeToString(new byte[] {1, 2, 3})));
                    byte[] transcript = transcript("invalid_key", StrictJson.object(withoutSignatures(operation)));
                    operation.put("signature", StrictJson.string(RegistryCrypto.encodeBase64(
                            RegistryCrypto.sign(player.getPrivate(), transcript))));
                    writeHistory(invalid, "invalid_key", List.of(StrictJson.object(operation)));
                    ClaimPipeline.loadAndResolve(invalid);
                });
    }

    static void strictJsonAndSchemaFailures() throws Exception {
        KeyPair player = keyPair();
        Path validRoot = Files.createTempDirectory("registry-json-");
        writeHistory(validRoot, "json_user", List.of(claim("json_user", player, null)));
        Path file = onlyClaim(validRoot);
        byte[] canonical = Files.readAllBytes(file);

        expectAny(RegistryFailure.Code.NON_CANONICAL_JSON, RegistryFailure.Code.MALFORMED_JSON, () -> {
            Path root = Files.createTempDirectory("registry-space-");
            writeRaw(root, "json_user", concat(" ".getBytes(StandardCharsets.UTF_8), canonical));
            ClaimPipeline.loadAndResolve(root);
        });
        expectAny(RegistryFailure.Code.DUPLICATE_FIELD, RegistryFailure.Code.NON_CANONICAL_JSON, () -> {
            Path root = Files.createTempDirectory("registry-duplicate-");
            String text = new String(canonical, StandardCharsets.UTF_8);
            String duplicate = text.replace("{\"handle\":", "{\"handle\":\"json_user\",\"handle\":");
            writeRaw(root, "json_user", duplicate.getBytes(StandardCharsets.UTF_8));
            ClaimPipeline.loadAndResolve(root);
        });
        expectCode(RegistryFailure.Code.UNKNOWN_FIELD, () -> {
            Path root = Files.createTempDirectory("registry-unknown-");
            StrictJson.ObjectValue parsed = StrictJson.requireObject(
                    StrictJson.parseCanonical(canonical, ClaimPipeline.MAXIMUM_CLAIM_BYTES), "claim");
            Map<String, StrictJson.Value> changed = new LinkedHashMap<>(parsed.values());
            changed.put("unknown", StrictJson.integer(1));
            writeRaw(root, "json_user", StrictJson.encode(StrictJson.object(changed)));
            ClaimPipeline.loadAndResolve(root);
        });
        expectCode(RegistryFailure.Code.MISSING_FIELD, () -> {
            Path root = Files.createTempDirectory("registry-missing-");
            StrictJson.ObjectValue parsed = StrictJson.requireObject(
                    StrictJson.parseCanonical(canonical, ClaimPipeline.MAXIMUM_CLAIM_BYTES), "claim");
            Map<String, StrictJson.Value> changed = new LinkedHashMap<>(parsed.values());
            changed.remove("policyVersion");
            writeRaw(root, "json_user", StrictJson.encode(StrictJson.object(changed)));
            ClaimPipeline.loadAndResolve(root);
        });
        expectCode(RegistryFailure.Code.MALFORMED_JSON, () -> {
            Path root = Files.createTempDirectory("registry-trailing-");
            writeRaw(root, "json_user", concat(canonical, "{}".getBytes(StandardCharsets.UTF_8)));
            ClaimPipeline.loadAndResolve(root);
        });
        expectCode(RegistryFailure.Code.MALFORMED_UTF8, () -> {
            Path root = Files.createTempDirectory("registry-utf8-");
            writeRaw(root, "json_user", new byte[] {(byte) 0xc3, 0x28});
            ClaimPipeline.loadAndResolve(root);
        });
    }

    static void pathReservedAndConfusablePolicy() throws Exception {
        KeyPair player = keyPair();
        expectCode(RegistryFailure.Code.INVALID_PATH, () -> {
            Path root = Files.createTempDirectory("registry-path-");
            StrictJson.ObjectValue operation = claim("path_user", player, null);
            byte[] bytes = history("path_user", List.of(operation));
            Path directory = root.resolve("ff");
            Files.createDirectories(directory);
            Files.write(directory.resolve("path_user.json"), bytes);
            ClaimPipeline.loadAndResolve(root);
        });
        expectCode(RegistryFailure.Code.INVALID_HANDLE, () -> {
            Path root = Files.createTempDirectory("registry-upper-");
            writeHistory(root, "UPPER_USER", List.of(claimUnchecked("UPPER_USER", player, null)));
            ClaimPipeline.loadAndResolve(root);
        });
        expectCode(RegistryFailure.Code.RESERVED_HANDLE, () -> {
            Path root = Files.createTempDirectory("registry-reserved-");
            writeHistory(root, "admin", List.of(claimUnchecked("admin", player, null)));
            ClaimPipeline.loadAndResolve(root);
        });
        expectCode(RegistryFailure.Code.CONFUSABLE_COLLISION, () -> {
            Path root = Files.createTempDirectory("registry-confusable-");
            writeHistory(root, "modern", List.of(claim("modern", player, null)));
            writeHistory(root, "rn0dern", List.of(claim("rn0dern", keyPair(), null)));
            ClaimPipeline.loadAndResolve(root);
        });
    }

    static void rotationAndRevokeLifecycle() throws Exception {
        KeyPair oldKey = keyPair();
        KeyPair newKey = keyPair();
        Path root = Files.createTempDirectory("registry-rotate-");
        writeHistory(
                root,
                "rotate_user",
                List.of(
                        claim("rotate_user", oldKey, "Before"),
                        rotate("rotate_user", 2, oldKey, newKey, "After"),
                        setDisplayName("rotate_user", 3, newKey, "Presented"),
                        revoke("rotate_user", 4, newKey)));
        ClaimPipeline.ResolvedClaim resolved = ClaimPipeline.loadAndResolve(root).claims().getFirst();
        equal(ClaimPipeline.Status.REVOKED, resolved.status(), "revoke status");
        equal(RegistryCrypto.playerId(newKey.getPublic()), resolved.playerId(), "rotated player ID");

        expectCode(RegistryFailure.Code.INVALID_SIGNATURE, () -> {
            Path invalid = Files.createTempDirectory("registry-old-proof-");
            StrictJson.ObjectValue rotation = rotate("missing_old", 2, oldKey, newKey, null);
            Map<String, StrictJson.Value> changed = new LinkedHashMap<>(rotation.values());
            changed.put("oldSignature", StrictJson.string(Base64.getEncoder().encodeToString(new byte[64])));
            writeHistory(invalid, "missing_old", List.of(claim("missing_old", oldKey, null), StrictJson.object(changed)));
            ClaimPipeline.loadAndResolve(invalid);
        });
        expectCode(RegistryFailure.Code.INVALID_SIGNATURE, () -> {
            Path invalid = Files.createTempDirectory("registry-new-proof-");
            StrictJson.ObjectValue rotation = rotate("missing_new", 2, oldKey, newKey, null);
            Map<String, StrictJson.Value> changed = new LinkedHashMap<>(rotation.values());
            changed.put("newSignature", StrictJson.string(Base64.getEncoder().encodeToString(new byte[64])));
            writeHistory(invalid, "missing_new", List.of(claim("missing_new", oldKey, null), StrictJson.object(changed)));
            ClaimPipeline.loadAndResolve(invalid);
        });
        expectCode(RegistryFailure.Code.INVALID_OPERATION, () -> {
            Path invalid = Files.createTempDirectory("registry-reactivate-");
            writeHistory(
                    invalid,
                    "revoked_user",
                    List.of(
                            claim("revoked_user", oldKey, null),
                            revoke("revoked_user", 2, oldKey),
                            rotate("revoked_user", 3, oldKey, newKey, null)));
            ClaimPipeline.loadAndResolve(invalid);
        });
    }

    static void deterministicResolutionAndSnapshot() throws Exception {
        KeyPair first = keyPair();
        KeyPair second = keyPair();
        List<ClaimPipeline.ClaimFile> files = List.of(
                parseInMemory("zeta_user", first), parseInMemory("alpha_user", second));
        List<ClaimPipeline.ClaimFile> reversed = new ArrayList<>(files);
        Collections.reverse(reversed);
        ClaimPipeline.Resolution a = ClaimPipeline.resolve(files);
        ClaimPipeline.Resolution b = ClaimPipeline.resolve(reversed);
        equal(a, b, "filesystem order independence");
        KeyPair root = keyPair();
        String rootB64 = RegistryCrypto.canonicalSpkiBase64(root.getPublic());
        SnapshotArtifacts.BuiltSnapshot firstSnapshot = SnapshotArtifacts.build(
                a, 11, "2026-08-02T00:00:00Z", rootB64);
        SnapshotArtifacts.BuiltSnapshot secondSnapshot = SnapshotArtifacts.build(
                b, 11, "2026-08-02T00:00:00Z", rootB64);
        bytes(firstSnapshot.canonicalJson(), secondSnapshot.canonicalJson(), "snapshot deterministic bytes");
        bytes(firstSnapshot.digest(), secondSnapshot.digest(), "snapshot deterministic digest");
    }

    static void publicConsumerVector() throws Exception {
        ClaimPipeline.ResolvedClaim entry = new ClaimPipeline.ResolvedClaim(
                "player_one", null, VECTOR_PLAYER, VECTOR_KEY, ClaimPipeline.Status.ACTIVE);
        SnapshotArtifacts.BuiltSnapshot snapshot = SnapshotArtifacts.build(
                new ClaimPipeline.Resolution(List.of(entry)),
                7,
                "2026-08-02T00:00:00Z",
                VECTOR_KEY);
        equal(VECTOR_JSON, new String(snapshot.canonicalJson(), StandardCharsets.UTF_8), "public vector JSON");
        equal(333, snapshot.canonicalJson().length, "public vector byte length");
        equal(
                "f160bf701d0e1291d50f958ac55941cc2fb63a4e9807ef9c847582affd9e3899",
                snapshot.digestHex(),
                "public vector digest");
    }

    static void detachedArtifactFailures() throws Exception {
        KeyPair player = keyPair();
        KeyPair root = keyPair();
        String rootB64 = RegistryCrypto.canonicalSpkiBase64(root.getPublic());
        Path claims = Files.createTempDirectory("registry-artifact-claims-");
        writeHistory(claims, "artifact_user", List.of(claim("artifact_user", player, null)));
        SnapshotArtifacts.BuiltSnapshot snapshot = SnapshotArtifacts.build(
                ClaimPipeline.loadAndResolve(claims),
                4,
                "2026-08-02T00:00:00Z",
                rootB64);
        Path output = Files.createTempDirectory("registry-artifact-");
        KeyPair overlapRoot = keyPair();
        String overlapRootB64 = RegistryCrypto.canonicalSpkiBase64(overlapRoot.getPublic());
        SnapshotArtifacts.signAndWrite(
                snapshot,
                Base64.getEncoder().encodeToString(root.getPrivate().getEncoded()),
                rootB64,
                List.of(overlapRootB64),
                output);
        SnapshotArtifacts.verifyDirectory(output, rootB64);
        String trustBundle = Files.readString(
                output.resolve(SnapshotArtifacts.TRUST_BUNDLE_FILE), StandardCharsets.UTF_8);
        check(trustBundle.contains(RegistryCrypto.rootKeyId(overlapRoot.getPublic())),
                "overlap root must be exported");
        check(trustBundle.contains("\"status\":\"OVERLAP\""),
                "overlap root status must be explicit");

        Path changedJson = copyDirectory(output);
        byte[] json = Files.readAllBytes(changedJson.resolve(SnapshotArtifacts.SNAPSHOT_FILE));
        json[json.length - 1] ^= 1;
        Files.write(changedJson.resolve(SnapshotArtifacts.SNAPSHOT_FILE), json);
        expectAny(RegistryFailure.Code.MALFORMED_JSON, RegistryFailure.Code.NON_CANONICAL_JSON, () ->
                SnapshotArtifacts.verifyDirectory(changedJson, rootB64));

        Path changedDigest = copyDirectory(output);
        Files.writeString(
                changedDigest.resolve(SnapshotArtifacts.DIGEST_FILE),
                "0".repeat(64) + "\n",
                StandardCharsets.US_ASCII);
        expectCode(RegistryFailure.Code.DIGEST_MISMATCH, () ->
                SnapshotArtifacts.verifyDirectory(changedDigest, rootB64));

        Path changedSignature = copyDirectory(output);
        Files.writeString(
                changedSignature.resolve(SnapshotArtifacts.SIGNATURE_FILE),
                Base64.getEncoder().encodeToString(new byte[64]) + "\n",
                StandardCharsets.US_ASCII);
        expectCode(RegistryFailure.Code.INVALID_SIGNATURE, () ->
                SnapshotArtifacts.verifyDirectory(changedSignature, rootB64));

        KeyPair unknown = keyPair();
        expectAny(RegistryFailure.Code.INVALID_SIGNATURE, RegistryFailure.Code.INVALID_ROOT, () ->
                SnapshotArtifacts.verifyDirectory(
                        output, RegistryCrypto.canonicalSpkiBase64(unknown.getPublic())));
    }

    static void missingRootSecretFailsClosed() throws Exception {
        expectCode(RegistryFailure.Code.SECRET_MISSING, () -> RegistryCrypto.requirePrivateKeySecret(null));
        expectCode(RegistryFailure.Code.SECRET_MISSING, () -> RegistryCrypto.requirePrivateKeySecret("  "));
    }

    static StrictJson.ObjectValue claim(String handle, KeyPair key, String displayName)
            throws Exception {
        HandlePolicy.validateHandle(handle);
        return claimUnchecked(handle, key, displayName);
    }

    static StrictJson.ObjectValue claimUnchecked(String handle, KeyPair key, String displayName)
            throws Exception {
        Map<String, StrictJson.Value> operation = new LinkedHashMap<>();
        operation.put("displayName", displayName == null ? StrictJson.nil() : StrictJson.string(displayName));
        operation.put("operation", StrictJson.string("CLAIM"));
        operation.put("playerId", StrictJson.string(RegistryCrypto.playerId(key.getPublic())));
        operation.put("publicKey", StrictJson.string(RegistryCrypto.canonicalSpkiBase64(key.getPublic())));
        operation.put("sequence", StrictJson.integer(1));
        operation.put("version", StrictJson.integer(1));
        byte[] transcript = transcript(handle, StrictJson.object(operation));
        operation.put("signature", StrictJson.string(RegistryCrypto.encodeBase64(
                RegistryCrypto.sign(key.getPrivate(), transcript))));
        return StrictJson.object(operation);
    }

    static StrictJson.ObjectValue rotate(
            String handle,
            long sequence,
            KeyPair oldKey,
            KeyPair newKey,
            String displayName)
            throws Exception {
        Map<String, StrictJson.Value> operation = new LinkedHashMap<>();
        operation.put("displayName", displayName == null ? StrictJson.nil() : StrictJson.string(displayName));
        operation.put("newPlayerId", StrictJson.string(RegistryCrypto.playerId(newKey.getPublic())));
        operation.put("newPublicKey", StrictJson.string(RegistryCrypto.canonicalSpkiBase64(newKey.getPublic())));
        operation.put("operation", StrictJson.string("ROTATE"));
        operation.put("previousPlayerId", StrictJson.string(RegistryCrypto.playerId(oldKey.getPublic())));
        operation.put("sequence", StrictJson.integer(sequence));
        operation.put("version", StrictJson.integer(1));
        byte[] transcript = transcript(handle, StrictJson.object(operation));
        operation.put("oldSignature", StrictJson.string(RegistryCrypto.encodeBase64(
                RegistryCrypto.sign(oldKey.getPrivate(), transcript))));
        operation.put("newSignature", StrictJson.string(RegistryCrypto.encodeBase64(
                RegistryCrypto.sign(newKey.getPrivate(), transcript))));
        return StrictJson.object(operation);
    }

    static StrictJson.ObjectValue setDisplayName(
            String handle, long sequence, KeyPair key, String displayName) throws Exception {
        Map<String, StrictJson.Value> operation = new LinkedHashMap<>();
        operation.put("displayName", displayName == null ? StrictJson.nil() : StrictJson.string(displayName));
        operation.put("operation", StrictJson.string("SET_DISPLAY_NAME"));
        operation.put("playerId", StrictJson.string(RegistryCrypto.playerId(key.getPublic())));
        operation.put("sequence", StrictJson.integer(sequence));
        operation.put("version", StrictJson.integer(1));
        byte[] transcript = transcript(handle, StrictJson.object(operation));
        operation.put("signature", StrictJson.string(RegistryCrypto.encodeBase64(
                RegistryCrypto.sign(key.getPrivate(), transcript))));
        return StrictJson.object(operation);
    }

    static StrictJson.ObjectValue revoke(String handle, long sequence, KeyPair key)
            throws Exception {
        Map<String, StrictJson.Value> operation = new LinkedHashMap<>();
        operation.put("operation", StrictJson.string("REVOKE"));
        operation.put("playerId", StrictJson.string(RegistryCrypto.playerId(key.getPublic())));
        operation.put("sequence", StrictJson.integer(sequence));
        operation.put("version", StrictJson.integer(1));
        byte[] transcript = transcript(handle, StrictJson.object(operation));
        operation.put("signature", StrictJson.string(RegistryCrypto.encodeBase64(
                RegistryCrypto.sign(key.getPrivate(), transcript))));
        return StrictJson.object(operation);
    }

    private static byte[] transcript(String handle, StrictJson.ObjectValue unsignedOperation)
            throws RegistryFailure {
        Map<String, StrictJson.Value> value = new LinkedHashMap<>();
        value.put("handle", StrictJson.string(handle));
        value.put("operation", unsignedOperation);
        value.put("policyVersion", StrictJson.integer(1));
        value.put("schema", StrictJson.integer(1));
        return StrictJson.encode(StrictJson.object(value));
    }

    private static Map<String, StrictJson.Value> withoutSignatures(Map<String, StrictJson.Value> source) {
        Map<String, StrictJson.Value> stripped = new LinkedHashMap<>(source);
        stripped.remove("signature");
        stripped.remove("oldSignature");
        stripped.remove("newSignature");
        return stripped;
    }

    private static byte[] history(String handle, List<StrictJson.ObjectValue> operations)
            throws RegistryFailure {
        Map<String, StrictJson.Value> root = new LinkedHashMap<>();
        root.put("handle", StrictJson.string(handle));
        root.put("operations", StrictJson.array(new ArrayList<>(operations)));
        root.put("policyVersion", StrictJson.integer(1));
        root.put("schema", StrictJson.integer(1));
        return StrictJson.encode(StrictJson.object(root));
    }

    private static void writeHistory(
            Path claimsRoot, String handle, List<StrictJson.ObjectValue> operations)
            throws Exception {
        writeRaw(claimsRoot, handle, history(handle, operations));
    }

    private static void writeRaw(Path claimsRoot, String handle, byte[] bytes) throws Exception {
        String prefix;
        try {
            prefix = RegistryCrypto.pathPrefix(handle);
        } catch (RegistryFailure failure) {
            prefix = "00";
        }
        Path directory = claimsRoot.resolve(prefix);
        Files.createDirectories(directory);
        Files.write(directory.resolve(handle + ".json"), bytes);
    }

    private static ClaimPipeline.ClaimFile parseInMemory(String handle, KeyPair key)
            throws Exception {
        Path root = Files.createTempDirectory("registry-memory-");
        writeHistory(root, handle, List.of(claim(handle, key, null)));
        return ClaimPipeline.loadFiles(root).getFirst();
    }

    private static Path onlyClaim(Path root) throws IOException {
        try (var stream = Files.walk(root)) {
            return stream.filter(Files::isRegularFile).findFirst().orElseThrow();
        }
    }

    private static Path copyDirectory(Path source) throws IOException {
        Path destination = Files.createTempDirectory("registry-copy-");
        try (var stream = Files.list(source)) {
            for (Path file : stream.toList()) {
                Files.copy(file, destination.resolve(file.getFileName()));
            }
        }
        return destination;
    }

    private static KeyPair keyPair() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = java.util.Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void equal(Object expected, Object actual, String message) {
        if (!java.util.Objects.equals(expected, actual)) {
            throw new AssertionError(message + ": expected=" + expected + ", actual=" + actual);
        }
    }

    private static void bytes(byte[] expected, byte[] actual, String message) {
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new AssertionError(message);
        }
    }

    private static void expectCode(RegistryFailure.Code code, ThrowingRunnable runnable)
            throws Exception {
        try {
            runnable.run();
        } catch (RegistryFailure failure) {
            equal(code, failure.code(), "failure code");
            return;
        }
        throw new AssertionError("expected RegistryFailure " + code);
    }

    private static void expectAny(
            RegistryFailure.Code first,
            RegistryFailure.Code second,
            ThrowingRunnable runnable)
            throws Exception {
        try {
            runnable.run();
        } catch (RegistryFailure failure) {
            if (failure.code() != first && failure.code() != second) {
                throw new AssertionError("unexpected failure code " + failure.code(), failure);
            }
            return;
        }
        throw new AssertionError("expected RegistryFailure " + first + " or " + second);
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
