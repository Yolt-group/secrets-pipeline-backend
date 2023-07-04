package com.yolt.secretspipeline.secrets;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.yolt.secretspipeline.secrets.Environments.AllEnvironments.allEnvironments;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecretDefinitionsTest {

    @Test
    @DisplayName("Given a secret definition when the private plaintext equals the public key then an exception must be throws")
    void privateKeyNotSameAsPublicKey() {
        var def = List.of(
                SecretDefinition.builder()
                        .name("test-secret")
                        .description("a test secret")
                        .projectName("test-project")
                        .gitlabRepoNamespace("test-repo")
                        .rotate(true)
                        .plaintextSecret(Base64String.encode("mysecret"))
                        .publicKeyOrCert(Base64String.encode("mysecret"))
                        .secretType(SecretType.KEY_128)
                        .environments(allEnvironments().findEnvironments("yfb-ext-prd"))
                        .build());

        assertThatThrownBy(() -> new SecretDefinitions(def))
                .hasMessageContaining("is the same as the public part");
    }
}