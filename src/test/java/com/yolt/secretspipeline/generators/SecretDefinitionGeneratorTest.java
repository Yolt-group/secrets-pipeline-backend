package com.yolt.secretspipeline.generators;

import com.yolt.secretspipeline.secrets.Base64String;
import com.yolt.secretspipeline.secrets.SecretDefinition;
import com.yolt.secretspipeline.secrets.SecretType;
import com.yolt.secretspipeline.secrets.VaultString;
import com.yolt.secretspipeline.vaultrunner.VaultRunnerHelper;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static com.yolt.secretspipeline.generators.SecretsGeneratorTest.POD_CERT;
import static com.yolt.secretspipeline.secrets.Environments.AllEnvironments.allEnvironments;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SecretDefinitionGeneratorTest {

    private final VaultRunnerHelper vaultRunnerHelper = mock(VaultRunnerHelper.class);
    private final SecretDefinitionGenerator gen = new SecretDefinitionGenerator(vaultRunnerHelper);

    @Test
    void nameInDeploymentFileWillBeTooLarge() {
        var def = Set.of(
                SecretDefinition.builder()
                        .environments(allEnvironments().findEnvironments("team9"))
                        .secretType(SecretType.PASSWORD_ALFA_NUMERIC)
                        .name("secret-payvision-username_PASSWORD_ALFA_NUMERIC_SPECIAL_CHARS")
                        .description("a test secret")
                        .projectName("test-project")
                        .gitlabRepoNamespace("test-namespace")
                        .build());

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> gen.extendWithRealSecret(def))
                .withMessageContaining("the secret exceeds the maximum length of 22 characters");
    }

    @Test
    void secretNameShouldNotContainCapitals() {
        var def = Set.of(
                SecretDefinition.builder()
                        .environments(allEnvironments().findEnvironments("team9"))
                        .secretType(SecretType.PASSWORD_ALFA_NUMERIC)
                        .name("THISISfun")
                        .description("a test secret")
                        .projectName("test-project")
                        .gitlabRepoNamespace("test-namespace")
                        .build());

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> gen.extendWithRealSecret(def))
                .withMessageContaining("The name of they key should not contain capitals!");
    }

    @Test
    void shouldCollectAllErrors() {
        var defs = Set.of(
                SecretDefinition.builder()
                        .environments(allEnvironments().findEnvironments("team9"))
                        .name("THISISfun")
                        .description("a test secret")
                        .projectName("test-project")
                        .gitlabRepoNamespace("test-namespace")
                        .secretType(SecretType.PASSWORD_ALFA_NUMERIC)
                        .build(),
                SecretDefinition.builder().environments(allEnvironments().findEnvironments("team9"))
                        .secretType(SecretType.PASSWORD_ALFA_NUMERIC)
                        .name("secret-payvision-username_PASSWORD_ALFA_NUMERIC_SPECIAL_CHARS")
                        .description("a test secret")
                        .projectName("test-project")
                        .gitlabRepoNamespace("test-namespace")
                        .build());

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> gen.extendWithRealSecret(defs))
                .withMessageContaining("The name of they key should not contain capitals!")
                .withMessageContaining("the secret exceeds the maximum length of 22 characters");
    }

    @Test
    @DisplayName("When a definition contains multiple environments then all plain text should be the same")
    void definitionWithMultipleEnvironments() {
        when(vaultRunnerHelper.dtaDecryptImportedSecret(any()))
                .thenReturn(Base64String.encode("testtesttest1"))
                .thenReturn(Base64String.encode("testtesttest2"));
        var def = Set.of(
                SecretDefinition.builder()
                        .environments(allEnvironments().findEnvironments("team11", "team4", "team9"))
                        .name("test")
                        .description("a test secret")
                        .projectName("test-project")
                        .gitlabRepoNamespace("test-namespace")
                        .secretType(SecretType.PASSWORD_ALFA_NUMERIC)
                        .build());

        assertThat(gen.extendWithRealSecret(def))
                .hasSize(1)
                .first()
                .extracting(d -> d.environments)
                .isEqualTo(allEnvironments().findEnvironments("team11", "team4", "team9"));
    }

    @Test
    @DisplayName("Given two definitions they should have a different generated secret")
    void shareOnlyBeDefinition() {
        var defs = Set.of(
                SecretDefinition.builder()
                        .environments(allEnvironments().findEnvironments("team4"))
                        .name("test")
                        .description("a test secret")
                        .projectName("test-project")
                        .gitlabRepoNamespace("test-namespace")
                        .secretType(SecretType.PASSWORD_ALFA_NUMERIC)
                        .build(),
                SecretDefinition.builder()
                        .environments(allEnvironments().findEnvironments("yfb-acc"))
                        .name("test")
                        .description("a test secret")
                        .projectName("test-project")
                        .gitlabRepoNamespace("test-namespace")
                        .secretType(SecretType.PASSWORD_ALFA_NUMERIC)
                        .build());

        var definitions = gen.extendWithRealSecret(defs);

        assertThat(definitions)
                .hasSize(2)
                .extracting(d -> d.environments)
                .containsExactlyInAnyOrder(allEnvironments().findEnvironments("team4"), allEnvironments().findEnvironments("yfb-acc"));
        assertThat(definitions)
                .extracting(d -> d.plaintextSecret).doesNotHaveDuplicates();
    }

    @Test
    @DisplayName("Given a secret definition for two dta and prd when the secret name is too long then two errors should be returned")
    void twoSecretsTooLong() {
        var defs = Set.of(
                SecretDefinition.builder()
                        .name(RandomStringUtils.randomAlphabetic(100))
                        .description("a test secret")
                        .projectName("test-project")
                        .gitlabRepoNamespace("test-namespace")
                        .rotate(true)
                        .plaintextSecret(Base64String.encode("mysecret"))
                        .secretType(SecretType.KEY_128)
                        .environments(allEnvironments().findEnvironments("yfb-acc", "team4"))
                        .build(),
                SecretDefinition.builder()
                        .name(RandomStringUtils.randomAlphabetic(100))
                        .description("a test secret")
                        .projectName("test-project")
                        .gitlabRepoNamespace("test-namespace")
                        .rotate(true)
                        .plaintextSecret(Base64String.encode("mysecret"))
                        .secretType(SecretType.KEY_128)
                        .environments(allEnvironments().findEnvironments("yfb-prd"))
                        .build());

        assertThatThrownBy(() -> gen.extendWithRealSecret(defs))
                .hasMessageContaining("(KEY_128) on environments [dta/team4/cluster2/ycs, dta/yfb-acc/cluster2/ycs]")
                .hasMessageContaining("(KEY_128) on environments [prd/yfb-prd/cluster2/ycs]");
    }

    @Test
    @DisplayName("When a certificate is imported without private key the secret should still be created")
    void certificateWithoutImportedSecret() {
        var def = Set.of(
                SecretDefinition.builder()
                        .name("certificate-import")
                        .description("a test secret")
                        .projectName("test-project")
                        .gitlabRepoNamespace("test-namespace")
                        .secretType(SecretType.CERT_ANY_IMPORT)
                        .publicKeyOrCert(Base64String.encode(POD_CERT))
                        .environments(allEnvironments().findEnvironments("team4"))
                        .build());

        var secretDefinitions = gen.extendWithRealSecret(def);

        assertThat(secretDefinitions).hasSize(1);
        assertThat(secretDefinitions).first().extracting(s -> s.importedSecret).isNull();
    }

    @Test
    @DisplayName("When a certificate is imported with private key the secret should contain both")
    void certificateWithImportedSecret() {
        var def = Set.of(
                SecretDefinition.builder()
                        .name("certificate-import")
                        .description("a test secret")
                        .projectName("test-project")
                        .gitlabRepoNamespace("test-namespace")
                        .importedSecret(VaultString.from("vault:v1:test"))
                        .secretType(SecretType.CERT_ANY_IMPORT)
                        .publicKeyOrCert(Base64String.encode(POD_CERT))
                        .environments(allEnvironments().findEnvironments("team4"))
                        .build());

        var secretDefinitions = gen.extendWithRealSecret(def);

        assertThat(secretDefinitions).hasSize(1);
        assertThat(secretDefinitions).first().extracting(s -> s.importedSecret).isNotNull();
    }
}