import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.HexFormat;

final class WrapperBootstrap {
    private static final URI SOURCE = URI.create(
            "https://raw.githubusercontent.com/grzegorz2047/StandaloneTheWalls/"
                    + "ed45d58db9a0b883ea1f7284324a205f33f16cba/gradle/wrapper/gradle-wrapper.jar");
    private static final String SHA256 =
            "497c8c2a7e5031f6aa847f88104aa80a93532ec32ee17bdb8d1d2f67a194a9c7";

    private WrapperBootstrap() {}

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 1) {
            throw new IllegalArgumentException("expected target wrapper JAR path");
        }
        Path target = Path.of(arguments[0]);
        if (Files.isRegularFile(target) && SHA256.equals(digest(Files.readAllBytes(target)))) {
            return;
        }
        HttpRequest request = HttpRequest.newBuilder(SOURCE).GET().build();
        HttpResponse<byte[]> response = HttpClient.newHttpClient()
                .send(request, HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) {
            throw new IOException("wrapper download failed with HTTP " + response.statusCode());
        }
        byte[] bytes = response.body();
        String actualSha256 = digest(bytes);
        if (!SHA256.equals(actualSha256)) {
            throw new SecurityException(
                    "downloaded Gradle wrapper JAR checksum mismatch: expected "
                            + SHA256
                            + " but received "
                            + actualSha256);
        }
        Files.createDirectories(target.getParent());
        Path temporary = target.resolveSibling(target.getFileName() + ".tmp");
        Files.write(temporary, bytes);
        Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    private static String digest(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
