package pl.grzegorz2047.standalonethewalls.registry;

/** Bounded semantic failure emitted by the registry authoring and release pipeline. */
public final class RegistryFailure extends Exception {
    private static final long serialVersionUID = 1L;

    public enum Code {
        IO,
        LIMIT_EXCEEDED,
        MALFORMED_UTF8,
        MALFORMED_JSON,
        NON_CANONICAL_JSON,
        DUPLICATE_FIELD,
        UNKNOWN_FIELD,
        MISSING_FIELD,
        INVALID_PATH,
        INVALID_HANDLE,
        RESERVED_HANDLE,
        CONFUSABLE_COLLISION,
        INVALID_DISPLAY_NAME,
        INVALID_SEQUENCE,
        INVALID_OPERATION,
        INVALID_PUBLIC_KEY,
        PLAYER_ID_MISMATCH,
        INVALID_SIGNATURE,
        INVALID_ROOT,
        DIGEST_MISMATCH,
        SECRET_MISSING,
        CRYPTOGRAPHY_FAILURE
    }

    private final Code code;

    public RegistryFailure(Code code, String message) {
        super(message);
        this.code = code;
    }

    public RegistryFailure(Code code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public Code code() {
        return code;
    }
}
