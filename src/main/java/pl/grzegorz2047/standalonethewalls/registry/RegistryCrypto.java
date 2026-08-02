package pl.grzegorz2047.standalonethewalls.registry;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;

/** Exact cryptographic conventions shared with the StandaloneTheWalls consumer. */
final class RegistryCrypto {
    private static final char[] BASE32 = "abcdefghijklmnopqrstuvwxyz234567".toCharArray();

    private RegistryCrypto() {
        throw new AssertionError("No instances");
    }

    static PublicKey decodeEd25519Spki(String base64) throws RegistryFailure {
        byte[] encoded = decodeCanonicalBase64(base64, "public key");
        try {
            PublicKey key = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(encoded));
            if (!Arrays.equals(encoded, key.getEncoded())) {
                throw new RegistryFailure(
                        RegistryFailure.Code.INVALID_PUBLIC_KEY,
                        "Ed25519 SubjectPublicKeyInfo is not canonical");
            }
            return key;
        } catch (RegistryFailure failure) {
            throw failure;
        } catch (GeneralSecurityException exception) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_PUBLIC_KEY,
                    "public key is not canonical Ed25519 X.509 SPKI",
                    exception);
        }
    }

    static PrivateKey decodeEd25519PrivateKey(String base64) throws RegistryFailure {
        byte[] encoded = decodeCanonicalBase64(base64, "private key");
        try {
            return KeyFactory.getInstance("Ed25519")
                    .generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (GeneralSecurityException exception) {
            throw new RegistryFailure(
                    RegistryFailure.Code.CRYPTOGRAPHY_FAILURE,
                    "private key is not Ed25519 PKCS#8",
                    exception);
        }
    }

    static String canonicalSpkiBase64(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    static String playerId(PublicKey key) throws RegistryFailure {
        return "sf1_" + base32(sha256(key.getEncoded()));
    }

    static String rootKeyId(PublicKey key) throws RegistryFailure {
        return "sfr1_" + base32(sha256(key.getEncoded()));
    }

    static String pathPrefix(String handle) throws RegistryFailure {
        return HexFormat.of().formatHex(sha256(handle.getBytes(java.nio.charset.StandardCharsets.UTF_8)), 0, 1);
    }

    static byte[] sha256(byte[] value) throws RegistryFailure {
        Objects.requireNonNull(value, "value");
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (GeneralSecurityException exception) {
            throw new RegistryFailure(
                    RegistryFailure.Code.CRYPTOGRAPHY_FAILURE, "SHA-256 is unavailable", exception);
        }
    }

    static String sha256Hex(byte[] value) throws RegistryFailure {
        return HexFormat.of().formatHex(sha256(value));
    }

    static byte[] sign(PrivateKey key, byte[] message) throws RegistryFailure {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(message, "message");
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(key);
            signature.update(message);
            return signature.sign();
        } catch (GeneralSecurityException exception) {
            throw new RegistryFailure(
                    RegistryFailure.Code.CRYPTOGRAPHY_FAILURE,
                    "Ed25519 signing failed internally",
                    exception);
        }
    }

    static boolean verify(PublicKey key, byte[] message, byte[] signatureBytes)
            throws RegistryFailure {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(signatureBytes, "signatureBytes");
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(key);
            signature.update(message);
            return signature.verify(signatureBytes);
        } catch (SignatureException exception) {
            return false;
        } catch (GeneralSecurityException exception) {
            throw new RegistryFailure(
                    RegistryFailure.Code.CRYPTOGRAPHY_FAILURE,
                    "Ed25519 verification failed internally",
                    exception);
        }
    }

    static byte[] decodeSignature(String base64) throws RegistryFailure {
        byte[] decoded = decodeCanonicalBase64(base64, "signature");
        if (decoded.length != 64) {
            throw new RegistryFailure(
                    RegistryFailure.Code.INVALID_SIGNATURE,
                    "Ed25519 signature must contain exactly 64 bytes");
        }
        return decoded;
    }

    static String encodeBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    static byte[] decodeCanonicalBase64(String value, String part) throws RegistryFailure {
        Objects.requireNonNull(value, "value");
        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            if (!Base64.getEncoder().encodeToString(decoded).equals(value)) {
                throw new RegistryFailure(
                        part.equals("signature")
                                ? RegistryFailure.Code.INVALID_SIGNATURE
                                : RegistryFailure.Code.INVALID_PUBLIC_KEY,
                        part + " is not canonical padded Base64");
            }
            return decoded;
        } catch (IllegalArgumentException exception) {
            throw new RegistryFailure(
                    part.equals("signature")
                            ? RegistryFailure.Code.INVALID_SIGNATURE
                            : RegistryFailure.Code.INVALID_PUBLIC_KEY,
                    part + " is not valid Base64",
                    exception);
        }
    }

    static String requirePrivateKeySecret() throws RegistryFailure {
        String secret = System.getenv("REGISTRY_ROOT_PRIVATE_KEY_PKCS8_B64");
        return requirePrivateKeySecret(secret);
    }

    static String requirePrivateKeySecret(String value) throws RegistryFailure {
        if (value == null || value.isBlank()) {
            throw new RegistryFailure(
                    RegistryFailure.Code.SECRET_MISSING,
                    "REGISTRY_ROOT_PRIVATE_KEY_PKCS8_B64 is required");
        }
        return value;
    }

    static String base32(byte[] value) {
        StringBuilder encoded = new StringBuilder((value.length * 8 + 4) / 5);
        int buffer = 0;
        int bits = 0;
        for (byte element : value) {
            buffer = (buffer << 8) | (element & 0xff);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                encoded.append(BASE32[(buffer >>> bits) & 0x1f]);
            }
        }
        if (bits > 0) {
            encoded.append(BASE32[(buffer << (5 - bits)) & 0x1f]);
        }
        return encoded.toString().toLowerCase(Locale.ROOT);
    }
}
