package pl.grzegorz2047.standalonethewalls.registry;

import org.junit.jupiter.api.Test;

class RegistryPipelineTest {
    @Test
    void validClaimAndSignatureFailures() throws Exception {
        RegistryTestSupport.validClaimAndSignatureFailures();
    }

    @Test
    void strictJsonAndSchemaFailures() throws Exception {
        RegistryTestSupport.strictJsonAndSchemaFailures();
    }

    @Test
    void pathReservedAndConfusablePolicy() throws Exception {
        RegistryTestSupport.pathReservedAndConfusablePolicy();
    }

    @Test
    void rotationAndRevokeLifecycle() throws Exception {
        RegistryTestSupport.rotationAndRevokeLifecycle();
    }

    @Test
    void deterministicResolutionAndSnapshot() throws Exception {
        RegistryTestSupport.deterministicResolutionAndSnapshot();
    }

    @Test
    void publicConsumerVector() throws Exception {
        RegistryTestSupport.publicConsumerVector();
    }

    @Test
    void detachedArtifactFailures() throws Exception {
        RegistryTestSupport.detachedArtifactFailures();
    }

    @Test
    void missingRootSecretFailsClosed() throws Exception {
        RegistryTestSupport.missingRootSecretFailsClosed();
    }
}
