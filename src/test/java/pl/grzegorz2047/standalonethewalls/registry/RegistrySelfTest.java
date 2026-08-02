package pl.grzegorz2047.standalonethewalls.registry;

/** Dependency-free entry point used for local hermetic verification. */
public final class RegistrySelfTest {
    private RegistrySelfTest() {
        throw new AssertionError("No instances");
    }

    public static void main(String[] arguments) throws Exception {
        RegistryTestSupport.runAll();
        System.out.println("registry self-test passed");
    }
}
