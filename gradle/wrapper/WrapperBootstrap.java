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
            "d81e0f23ade952b35e55333dd5f1821585e887c6d24305aeea2fbc8dad564b95";

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
        if (!SHA256.equals(digest(bytes))) {
            throw new SecurityException("downloaded Gradle wrapper JAR checksum mismatch");
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
