package pl.grzegorz2047.standalonethewalls.registry;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Objects;

/** Exact snapshot-v1 writer plus detached digest, signature, trust and manifest artifacts. */
final class SnapshotArtifacts {
    static final int SNAPSHOT_SCHEMA_VERSION = 1;
    static final String SNAPSHOT_FILE = "registry-v1.json";
    static final String DIGEST_FILE = "registry-v1.sha256";
    static final String SIGNATURE_FILE = "registry-v1.sig";
    static final String TRUST_BUNDLE_FILE = "registry-trust-v1.json";
    static final String MANIFEST_FILE = "registry-manifest-v1.json";

    record BuiltSnapshot(
            byte[] canonicalJson,
            byte[] digest,
            String digestHex,
            String rootKeyId,
            long sequence,
            Instant generatedAt) {
        BuiltSnapshot {
            canonicalJson = canonicalJson.clone();
            digest = digest.clone();
        }

        @Override
        public byte[] canonicalJson() {
            return canonicalJson.clone();
        }

        @Override
        public byte[] digest() {
            return digest.clone();
        }
    }

    private SnapshotArtifacts() {
        throw new AssertionError("No instances");
    }

    static BuiltSnapshot build(
            ClaimPipeline.Resolution resolution,
            long sequence,
            String generatedAtText,
            String rootPublicKeyBase64)
            throws RegistryFailure {
        if (sequence < 0) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_SEQUENCE, "snapshot sequence cannot be negative");
        }
        Instant generatedAt;
        try {
            generatedAt = Instant.parse(generatedAtText);
            if (!generatedAt.toString().equals(generatedAtText)) {
                throw new RegistryFailure(
                        RegistryFailure.Code.INVALID_OPERATION,
                        "generatedAt must be canonical Instant.toString() UTC text");
            }
        } catch (DateTimeException exception) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_OPERATION,
                    "generatedAt is not a valid canonical UTC instant",
                    exception);
        }
        PublicKey root = RegistryCrypto.decodeEd25519Spki(rootPublicKeyBase64);
        String rootKeyId = RegistryCrypto.rootKeyId(root);
        List<StrictJson.Value> entries = new ArrayList<>();
        String previous = null;
        for (ClaimPipeline.ResolvedClaim claim : resolution.claims()) {
            if (previous != null && previous.compareTo(claim.handle()) >= 0) {
                throw new RegistryFailure(
                        RegistryFailure.Code.INVALID_OPERATION,
                        "resolved claims are not strictly ordered");
            }
            previous = claim.handle();
            Map<String, StrictJson.Value> entry = new LinkedHashMap<>();
            entry.put("handle", StrictJson.string(claim.handle()));
            entry.put("playerId", StrictJson.string(claim.playerId()));
            entry.put("publicKey", StrictJson.string(claim.publicKeyBase64()));
            entry.put("status", StrictJson.string(claim.status().name()));
            entries.add(StrictJson.object(entry));
        }
        Map<String, StrictJson.Value> payload = new LinkedHashMap<>();
        payload.put("entries", StrictJson.array(entries));
        payload.put("generatedAt", StrictJson.string(generatedAtText));
        payload.put("rootKeyId", StrictJson.string(rootKeyId));
        payload.put("schema", StrictJson.integer(SNAPSHOT_SCHEMA_VERSION));
        payload.put("sequence", StrictJson.integer(sequence));
        byte[] canonical = StrictJson.encode(StrictJson.object(payload));
        byte[] digest = RegistryCrypto.sha256(canonical);
        return new BuiltSnapshot(
                canonical,
                digest,
                java.util.HexFormat.of().formatHex(digest),
                rootKeyId,
                sequence,
                generatedAt);
    }

    static void writeUnsigned(BuiltSnapshot snapshot, String rootPublicKeyBase64, Path output)
            throws RegistryFailure {
        createCleanDirectory(output);
        write(output.resolve(SNAPSHOT_FILE), snapshot.canonicalJson(), false);
        write(
                output.resolve(DIGEST_FILE),
                (snapshot.digestHex() + "\n").getBytes(StandardCharsets.US_ASCII),
                false);
        write(
                output.resolve(TRUST_BUNDLE_FILE),
                trustBundle(snapshot, rootPublicKeyBase64, List.of()),
                false);
        write(output.resolve(MANIFEST_FILE), manifest(snapshot, false), false);
    }

    static void signAndWrite(
            BuiltSnapshot snapshot,
            String rootPrivateKeyBase64,
            String rootPublicKeyBase64,
            Path output)
            throws RegistryFailure {
        signAndWrite(snapshot, rootPrivateKeyBase64, rootPublicKeyBase64, List.of(), output);
    }

    static void signAndWrite(
            BuiltSnapshot snapshot,
            String rootPrivateKeyBase64,
            String rootPublicKeyBase64,
            List<String> overlapRootPublicKeys,
            Path output)
            throws RegistryFailure {
        PublicKey publicKey = RegistryCrypto.decodeEd25519Spki(rootPublicKeyBase64);
        if (!RegistryCrypto.rootKeyId(publicKey).equals(snapshot.rootKeyId())) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_ROOT,
                    "signing public key does not match snapshot rootKeyId");
        }
        PrivateKey privateKey = RegistryCrypto.decodeEd25519PrivateKey(
                RegistryCrypto.requirePrivateKeySecret(rootPrivateKeyBase64));
        byte[] signature = RegistryCrypto.sign(privateKey, snapshot.canonicalJson());
        if (!RegistryCrypto.verify(publicKey, snapshot.canonicalJson(), signature)) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_ROOT,
                    "root private key does not correspond to the declared public key");
        }
        createCleanDirectory(output);
        write(output.resolve(SNAPSHOT_FILE), snapshot.canonicalJson(), false);
        write(
                output.resolve(DIGEST_FILE),
                (snapshot.digestHex() + "\n").getBytes(StandardCharsets.US_ASCII),
                false);
        write(
                output.resolve(SIGNATURE_FILE),
                (Base64.getEncoder().encodeToString(signature) + "\n")
                        .getBytes(StandardCharsets.US_ASCII),
                false);
        write(
                output.resolve(TRUST_BUNDLE_FILE),
                trustBundle(snapshot, rootPublicKeyBase64, overlapRootPublicKeys),
                false);
        write(output.resolve(MANIFEST_FILE), manifest(snapshot, true), false);
        verifyDirectory(output, rootPublicKeyBase64);
    }

    static void verifyDirectory(Path directory, String rootPublicKeyBase64)
            throws RegistryFailure {
        byte[] json = readBounded(directory.resolve(SNAPSHOT_FILE), 16_777_216);
        StrictJson.parseCanonical(json, 16_777_216);
        String digestText = new String(
                        readBounded(directory.resolve(DIGEST_FILE), 256), StandardCharsets.US_ASCII)
                .strip();
        if (!digestText.matches("[0-9a-f]{64}")) {
            throw new RegistryFailure(
                    RegistryFailure.Code.DIGEST_MISMATCH,
                    "detached digest is not lowercase hexadecimal SHA-256");
        }
        byte[] actualDigest = RegistryCrypto.sha256(json);
        byte[] declaredDigest = java.util.HexFormat.of().parseHex(digestText);
        if (!MessageDigest.isEqual(actualDigest, declaredDigest)) {
            throw new RegistryFailure(
                    RegistryFailure.Code.DIGEST_MISMATCH,
                    "detached digest does not match exact snapshot bytes");
        }
        PublicKey root = RegistryCrypto.decodeEd25519Spki(rootPublicKeyBase64);
        byte[] signature = RegistryCrypto.decodeSignature(
                new String(
                                readBounded(directory.resolve(SIGNATURE_FILE), 1024),
                                StandardCharsets.US_ASCII)
                        .strip());
        if (!RegistryCrypto.verify(root, json, signature)) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_SIGNATURE,
                    "detached root signature does not match exact snapshot bytes");
        }
        StrictJson.ObjectValue payload = StrictJson.requireObject(
                StrictJson.parseCanonical(json, 16_777_216), "snapshot");
        String declaredRoot = StrictJson.requireString(
                Objects.requireNonNull(payload.values().get("rootKeyId")), "rootKeyId");
        if (!declaredRoot.equals(RegistryCrypto.rootKeyId(root))) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_ROOT,
                    "snapshot rootKeyId is not the configured root");
        }
        verifyTrustBundle(directory.resolve(TRUST_BUNDLE_FILE), declaredRoot);
    }

    static List<String> readOverlapRoots(Path path) throws RegistryFailure {
        byte[] encoded = readBoundedAllowEmpty(path, 65_536);
        if (encoded.length == 0) {
            return List.of();
        }
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(encoded))
                    .toString();
        } catch (java.nio.charset.CharacterCodingException exception) {
            throw new RegistryFailure(
                    RegistryFailure.Code.MALFORMED_UTF8,
                    "overlap root list is not strict UTF-8",
                    exception);
        }
        List<String> roots = text.lines().map(String::strip).filter(line -> !line.isEmpty()).toList();
        if (roots.size() > 7) {
            throw new RegistryFailure(
                    RegistryFailure.Code.LIMIT_EXCEEDED,
                    "at most seven overlap roots are allowed");
        }
        return roots;
    }

    private static byte[] trustBundle(
            BuiltSnapshot snapshot, String publicKey, List<String> overlapRootPublicKeys)
            throws RegistryFailure {
        record RootMaterial(String rootKeyId, String publicKey, String status) {}
        PublicKey activeKey = RegistryCrypto.decodeEd25519Spki(publicKey);
        String canonicalActive = RegistryCrypto.canonicalSpkiBase64(activeKey);
        List<RootMaterial> materials = new ArrayList<>();
        materials.add(new RootMaterial(snapshot.rootKeyId(), canonicalActive, "ACTIVE"));
        Set<String> rootIds = new HashSet<>();
        rootIds.add(snapshot.rootKeyId());
        for (String overlap : overlapRootPublicKeys) {
            PublicKey decoded = RegistryCrypto.decodeEd25519Spki(overlap);
            String rootKeyId = RegistryCrypto.rootKeyId(decoded);
            if (!rootIds.add(rootKeyId)) {
                throw new RegistryFailure(
                        RegistryFailure.Code.INVALID_ROOT,
                        "trust bundle contains a duplicate root");
            }
            materials.add(new RootMaterial(
                    rootKeyId, RegistryCrypto.canonicalSpkiBase64(decoded), "OVERLAP"));
        }
        materials.sort(Comparator.comparing(RootMaterial::rootKeyId));
        List<StrictJson.Value> roots = new ArrayList<>();
        for (RootMaterial material : materials) {
            Map<String, StrictJson.Value> root = new LinkedHashMap<>();
            root.put("acceptedFromSequence", StrictJson.integer(snapshot.sequence()));
            root.put("publicKey", StrictJson.string(material.publicKey()));
            root.put("rootKeyId", StrictJson.string(material.rootKeyId()));
            root.put("status", StrictJson.string(material.status()));
            roots.add(StrictJson.object(root));
        }
        Map<String, StrictJson.Value> bundle = new LinkedHashMap<>();
        bundle.put("roots", StrictJson.array(roots));
        bundle.put("schema", StrictJson.integer(1));
        return StrictJson.encode(StrictJson.object(bundle));
    }

    private static void verifyTrustBundle(Path path, String activeRootId) throws RegistryFailure {
        StrictJson.ObjectValue bundle = StrictJson.requireObject(
                StrictJson.parseCanonical(readBounded(path, 65_536), 65_536), "trust bundle");
        requireExactFields(bundle, Set.of("roots", "schema"), "trust bundle");
        if (StrictJson.requireInteger(bundle.values().get("schema"), "schema") != 1) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_ROOT, "trust bundle schema is unsupported");
        }
        StrictJson.ArrayValue roots = StrictJson.requireArray(bundle.values().get("roots"), "roots");
        if (roots.values().isEmpty() || roots.values().size() > 8) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_ROOT, "trust bundle root count is invalid");
        }
        Set<String> identifiers = new HashSet<>();
        boolean activeFound = false;
        for (StrictJson.Value value : roots.values()) {
            StrictJson.ObjectValue root = StrictJson.requireObject(value, "root");
            requireExactFields(
                    root,
                    Set.of("acceptedFromSequence", "publicKey", "rootKeyId", "status"),
                    "root");
            long acceptedFrom = StrictJson.requireInteger(
                    root.values().get("acceptedFromSequence"), "acceptedFromSequence");
            if (acceptedFrom < 0) {
                throw new RegistryFailure(
                        RegistryFailure.Code.INVALID_ROOT,
                        "root acceptedFromSequence cannot be negative");
            }
            String publicKeyText = StrictJson.requireString(root.values().get("publicKey"), "publicKey");
            PublicKey decoded = RegistryCrypto.decodeEd25519Spki(publicKeyText);
            String derived = RegistryCrypto.rootKeyId(decoded);
            String declared = StrictJson.requireString(root.values().get("rootKeyId"), "rootKeyId");
            if (!derived.equals(declared) || !identifiers.add(declared)) {
                throw new RegistryFailure(
                        RegistryFailure.Code.INVALID_ROOT,
                        "trust bundle root identity is invalid or duplicated");
            }
            String status = StrictJson.requireString(root.values().get("status"), "status");
            if (!status.equals("ACTIVE") && !status.equals("OVERLAP")) {
                throw new RegistryFailure(
                        RegistryFailure.Code.INVALID_ROOT, "trust bundle root status is unsupported");
            }
            if (declared.equals(activeRootId)) {
                if (!status.equals("ACTIVE")) {
                    throw new RegistryFailure(
                            RegistryFailure.Code.INVALID_ROOT,
                            "snapshot signing root must be ACTIVE in the trust bundle");
                }
                activeFound = true;
            }
        }
        if (!activeFound) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_ROOT,
                    "trust bundle does not contain the snapshot signing root");
        }
    }

    private static void requireExactFields(
            StrictJson.ObjectValue object, Set<String> expected, String part)
            throws RegistryFailure {
        if (!object.values().keySet().equals(expected)) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_ROOT,
                    part + " contains unknown or missing fields");
        }
    }

    private static byte[] manifest(BuiltSnapshot snapshot, boolean signed)
            throws RegistryFailure {
        Map<String, StrictJson.Value> assets = new LinkedHashMap<>();
        assets.put("digest", StrictJson.string(DIGEST_FILE));
        assets.put("manifest", StrictJson.string(MANIFEST_FILE));
        assets.put("signature", signed ? StrictJson.string(SIGNATURE_FILE) : StrictJson.nil());
        assets.put("snapshot", StrictJson.string(SNAPSHOT_FILE));
        assets.put("trustBundle", StrictJson.string(TRUST_BUNDLE_FILE));
        Map<String, StrictJson.Value> manifest = new LinkedHashMap<>();
        manifest.put("assets", StrictJson.object(assets));
        manifest.put("generatedAt", StrictJson.string(snapshot.generatedAt().toString()));
        manifest.put("rootKeyId", StrictJson.string(snapshot.rootKeyId()));
        manifest.put("schema", StrictJson.integer(1));
        manifest.put("sequence", StrictJson.integer(snapshot.sequence()));
        manifest.put("snapshotSha256", StrictJson.string(snapshot.digestHex()));
        manifest.put("snapshotSigned", StrictJson.bool(signed));
        return StrictJson.encode(StrictJson.object(manifest));
    }

    private static void createCleanDirectory(Path output) throws RegistryFailure {
        try {
            if (Files.exists(output, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                if (!Files.isDirectory(output, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                    throw new RegistryFailure(
                            RegistryFailure.Code.INVALID_PATH,
                            "artifact output must be a directory");
                }
                try (var stream = Files.list(output)) {
                    if (stream.findAny().isPresent()) {
                        throw new RegistryFailure(
                                RegistryFailure.Code.INVALID_PATH,
                                "artifact output directory must be empty");
                    }
                }
            } else {
                Files.createDirectories(output);
            }
        } catch (RegistryFailure failure) {
            throw failure;
        } catch (IOException exception) {
            throw new RegistryFailure(
                    RegistryFailure.Code.IO, "artifact output could not be prepared", exception);
        }
    }

    private static void write(Path path, byte[] bytes, boolean replace) throws RegistryFailure {
        try {
            if (replace) {
                Files.write(
                        path,
                        bytes,
                        StandardOpenOption.CREATE,
                        StandardOpenOption.TRUNCATE_EXISTING,
                        StandardOpenOption.WRITE);
            } else {
                Files.write(path, bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            }
        } catch (IOException exception) {
            throw new RegistryFailure(
                    RegistryFailure.Code.IO, "artifact file could not be written", exception);
        }
    }

    private static byte[] readBoundedAllowEmpty(Path path, int maximumBytes)
            throws RegistryFailure {
        try {
            long size = Files.size(path);
            if (size < 0 || size > maximumBytes || !Files.isRegularFile(path)) {
                throw new RegistryFailure(
                        RegistryFailure.Code.LIMIT_EXCEEDED,
                        "file size is outside the safe range");
            }
            return Files.readAllBytes(path);
        } catch (RegistryFailure failure) {
            throw failure;
        } catch (IOException exception) {
            throw new RegistryFailure(
                    RegistryFailure.Code.IO, "file could not be read", exception);
        }
    }

    private static byte[] readBounded(Path path, int maximumBytes) throws RegistryFailure {
        try {
            long size = Files.size(path);
            if (size <= 0 || size > maximumBytes || !Files.isRegularFile(path)) {
                throw new RegistryFailure(
                        RegistryFailure.Code.LIMIT_EXCEEDED,
                        "artifact file size is outside the safe range");
            }
            return Files.readAllBytes(path);
        } catch (RegistryFailure failure) {
            throw failure;
        } catch (IOException exception) {
            throw new RegistryFailure(
                    RegistryFailure.Code.IO, "artifact file could not be read", exception);
        }
    }
}
