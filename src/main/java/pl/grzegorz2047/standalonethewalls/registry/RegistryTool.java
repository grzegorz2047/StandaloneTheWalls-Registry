package pl.grzegorz2047.standalonethewalls.registry;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/** Command-line entry point used by contributor and protected release workflows. */
public final class RegistryTool {
    private RegistryTool() {
        throw new AssertionError("No instances");
    }

    public static void main(String[] arguments) {
        try {
            run(arguments);
        } catch (RegistryFailure failure) {
            System.err.println("registry-error[" + failure.code() + "]: " + failure.getMessage());
            System.exit(2);
        } catch (RuntimeException failure) {
            System.err.println("registry-error[INTERNAL]: bounded registry operation failed");
            System.exit(3);
        }
    }

    static void run(String[] arguments) throws RegistryFailure {
        if (arguments.length == 0) {
            usage();
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_OPERATION, "command is required");
        }
        switch (arguments[0]) {
            case "validate" -> {
                requireCount(arguments, 2);
                ClaimPipeline.Resolution resolution = ClaimPipeline.loadAndResolve(Path.of(arguments[1]));
                System.out.println("validated " + resolution.claims().size() + " claim histories");
            }
            case "build-snapshot" -> {
                requireCount(arguments, 6);
                ClaimPipeline.Resolution resolution = ClaimPipeline.loadAndResolve(Path.of(arguments[1]));
                long sequence = parseSequence(arguments[2]);
                SnapshotArtifacts.BuiltSnapshot snapshot = SnapshotArtifacts.build(
                        resolution, sequence, arguments[3], arguments[4]);
                SnapshotArtifacts.writeUnsigned(snapshot, arguments[4], Path.of(arguments[5]));
                System.out.println(snapshot.digestHex());
            }
            case "release" -> {
                requireCount(arguments, 7);
                ClaimPipeline.Resolution resolution = ClaimPipeline.loadAndResolve(Path.of(arguments[1]));
                long sequence = parseSequence(arguments[2]);
                SnapshotArtifacts.BuiltSnapshot snapshot = SnapshotArtifacts.build(
                        resolution, sequence, arguments[3], arguments[4]);
                SnapshotArtifacts.signAndWrite(
                        snapshot,
                        RegistryCrypto.requirePrivateKeySecret(),
                        arguments[4],
                        SnapshotArtifacts.readOverlapRoots(Path.of(arguments[5])),
                        Path.of(arguments[6]));
                System.out.println(snapshot.digestHex());
            }
            case "verify-artifact" -> {
                requireCount(arguments, 3);
                SnapshotArtifacts.verifyDirectory(Path.of(arguments[1]), arguments[2]);
                System.out.println("artifact verified");
            }
            case "prefix" -> {
                requireCount(arguments, 2);
                HandlePolicy.validateHandle(arguments[1]);
                System.out.println(RegistryCrypto.pathPrefix(arguments[1]));
            }
            case "player-id" -> {
                requireCount(arguments, 2);
                System.out.println(RegistryCrypto.playerId(
                        RegistryCrypto.decodeEd25519Spki(arguments[1])));
            }
            case "root-id" -> {
                requireCount(arguments, 2);
                System.out.println(RegistryCrypto.rootKeyId(
                        RegistryCrypto.decodeEd25519Spki(arguments[1])));
            }
            case "transcript" -> {
                requireCount(arguments, 5);
                ClaimPipeline.ClaimFile claim = ClaimPipeline.parseFile(
                        Path.of(arguments[1]), Path.of(arguments[2]));
                int index;
                try {
                    index = Integer.parseInt(arguments[3]);
                } catch (NumberFormatException exception) {
                    throw new RegistryFailure(
                            RegistryFailure.Code.INVALID_OPERATION,
                            "operation index must be an integer",
                            exception);
                }
                if (index < 0 || index >= claim.operations().size()) {
                    throw new RegistryFailure(
                            RegistryFailure.Code.INVALID_OPERATION,
                            "operation index is outside the claim history");
                }
                try {
                    Files.write(Path.of(arguments[4]), claim.operations().get(index).transcript());
                } catch (java.io.IOException exception) {
                    throw new RegistryFailure(
                            RegistryFailure.Code.IO, "transcript could not be written", exception);
                }
            }
            case "canonicalize" -> {
                requireCount(arguments, 3);
                byte[] input;
                try {
                    input = Files.readAllBytes(Path.of(arguments[1]));
                    Files.write(Path.of(arguments[2]), StrictJson.encode(
                            StrictJson.parse(input, ClaimPipeline.MAXIMUM_CLAIM_BYTES)));
                } catch (java.io.IOException exception) {
                    throw new RegistryFailure(
                            RegistryFailure.Code.IO, "JSON could not be canonicalized", exception);
                }
            }
            default -> {
                usage();
                throw new RegistryFailure(
                        RegistryFailure.Code.INVALID_OPERATION, "command is unsupported");
            }
        }
    }

    private static long parseSequence(String value) throws RegistryFailure {
        try {
            long sequence = Long.parseLong(value);
            if (sequence < 0) {
                throw new NumberFormatException("negative");
            }
            return sequence;
        } catch (NumberFormatException exception) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_SEQUENCE,
                    "sequence must be a non-negative signed 64-bit integer",
                    exception);
        }
    }

    private static void requireCount(String[] arguments, int expected) throws RegistryFailure {
        if (arguments.length != expected) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_OPERATION,
                    "unexpected arguments: " + Arrays.toString(arguments));
        }
    }

    private static void usage() {
        System.err.println("Usage:");
        System.err.println("  validate <claims-dir>");
        System.err.println("  build-snapshot <claims-dir> <sequence> <generatedAt> <root-spki-b64> <empty-output-dir>");
        System.err.println("  release <claims-dir> <sequence> <generatedAt> <root-spki-b64> <overlap-roots-file> <empty-output-dir>");
        System.err.println("  verify-artifact <artifact-dir> <root-spki-b64>");
        System.err.println("  prefix <canonical-handle>");
        System.err.println("  player-id <player-spki-b64>");
        System.err.println("  root-id <root-spki-b64>");
        System.err.println("  transcript <claims-dir> <claim-file> <zero-based-operation-index> <output-file>");
        System.err.println("  canonicalize <input-json> <output-json>");
    }
}
