package com.yolt.secretspipeline.generators;

import com.yolt.secretspipeline.command.Options;
import com.yolt.secretspipeline.secrets.Base64String;
import com.yolt.secretspipeline.secrets.Environment;
import com.yolt.secretspipeline.secrets.Environments;
import com.yolt.secretspipeline.secrets.Secret;
import com.yolt.secretspipeline.secrets.SecretDefinition;
import com.yolt.secretspipeline.secrets.SecretType;
import com.yolt.secretspipeline.secrets.Secrets;
import com.yolt.secretspipeline.secrets.Environments.Namespace;
import com.yolt.secretspipeline.vaultrunner.VaultRunnerHelperLocal;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static com.yolt.secretspipeline.secrets.Environments.AllEnvironments.allEnvironments;
import static com.yolt.secretspipeline.secrets.SecretType.CERT_ANY_IMPORT;
import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;

class ProjectSecretsGeneratorTest {

    private final SecretDefinitionGenerator secretDefinitionGenerator = new SecretDefinitionGenerator(new VaultRunnerHelperLocal());
    private final SecretsGenerator generator = new SecretsGenerator(new VaultRunnerHelperLocal());

    @Test
    @DisplayName("When adding a new secret definition is should be part of the secrets")
    void addingNewSecretDefinition() {
        var definition = SecretDefinition.builder()
                .name("key")
                .description("a test secret")
                .projectName("yolt-sse")
                .gitlabRepoNamespace("test-namespace")
                .plaintextSecret(Base64String.encode("mysecret"))
                .secretType(SecretType.KEY_128)
                .environments(Environments.AllEnvironments.allEnvironments().findEnvironments("team4"))
                .build();
        var projectSecretsGenerator = new ProjectSecretsGenerator(secretDefinitionGenerator, generator, new Options(true, false, "Test MR"));

        var secrets = projectSecretsGenerator.update(Set.of(definition), new Secrets(emptyList()));

        assertThat(secrets.size()).isEqualTo(1);
    }

    @Test
    @DisplayName("Given existing secret when adding a new secret definition then both should be part of the secrets")
    void addingNewSecretDefinitionToExistingSecretes() {
        var secrets = new Secrets(List.of(Secret.builder()
                .secretType(CERT_ANY_IMPORT)
                .secretName("existing_secret")
                .vaultPath("team4-ycs-stubs")
                .environment(findEnvironments("team4", Namespace.YCS))
                .build()));

        var newDefinition = SecretDefinition.builder()
                .name("new_secret")
                .description("a test secret")
                .projectName("test-project")
                .gitlabRepoNamespace("test-namespace")
                .projectName("stubs")
                .plaintextSecret(Base64String.encode("mysecret"))
                .secretType(SecretType.KEY_128)
                .environments(allEnvironments().findEnvironments("team4"))
                .build();

        var projectSecretsGenerator = new ProjectSecretsGenerator(secretDefinitionGenerator, generator, new Options(true, false, "Test MR"));

        var updatedSecrets = projectSecretsGenerator.update(Set.of(newDefinition), secrets);

        assertThat(updatedSecrets.getYoltSecrets()).hasSize(2);
        assertThat(updatedSecrets.getYoltSecrets()).extracting(Secret::getSecretName).contains("new_secret", "existing_secret");
    }

    @Test
    @DisplayName("When rotate is set to true existing secret should be replaced")
    void rotateExistingSecret() {
        var definition = SecretDefinition.builder()
                .name("key")
                .description("a test secret")
                .projectName("test-project")
                .gitlabRepoNamespace("test-namespace")
                .rotate(true)
                .plaintextSecret(Base64String.encode("mysecret"))
                .secretType(SecretType.KEY_128)
                .environments(allEnvironments().findEnvironments("team4"))
                .build();
        var projectSecretsGenerator = new ProjectSecretsGenerator(secretDefinitionGenerator, generator, new Options(true, false, "Test MR"));
        var secrets = projectSecretsGenerator.update(Set.of(definition), new Secrets(emptyList()));
        var cipherText = secrets.getYoltSecrets().get(0).content;

        secrets = projectSecretsGenerator.update(Set.of(definition), new Secrets(emptyList()));

        assertThat(secrets.getYoltSecrets().get(0).content).isNotEqualTo(cipherText);
    }

    @Test
    @DisplayName("When multiple environments are specified multiple secrets should be generated")
    void multipleEnvironments() {
        var definition = SecretDefinition.builder()
                .name("key")
                .description("a test secret")
                .projectName("test-project")
                .gitlabRepoNamespace("test-namespace")
                .rotate(true)
                .plaintextSecret(Base64String.encode("mysecret"))
                .secretType(SecretType.KEY_128)
                .environments(allEnvironments().findEnvironments("team4", "team9"))
                .build();
        var projectSecretsGenerator = new ProjectSecretsGenerator(secretDefinitionGenerator, generator, new Options(true, false, "Test MR"));

        var secrets = projectSecretsGenerator.update(Set.of(definition), new Secrets(emptyList()));

        assertThat(secrets.getYoltSecrets()).hasSize(2);
    }

    @Test
    @DisplayName("When two secrets have an error both should be reported at once")
    void multipleErrors() {
        var definition1 = SecretDefinition.builder()
                .name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .description("a test secret")
                .projectName("test-project")
                .gitlabRepoNamespace("test-namespace")
                .rotate(true)
                .plaintextSecret(Base64String.encode("mysecret"))
                .secretType(SecretType.KEY_128)
                .environments(allEnvironments().findEnvironments("team4", "team9"))
                .build();
        var definition2 = definition1.toBuilder().name("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").build();
        var projectSecretsGenerator = new ProjectSecretsGenerator(secretDefinitionGenerator, generator, new Options(true, false, "Test MR"));

        Assertions.assertThatThrownBy(
                () -> projectSecretsGenerator.update(Set.of(definition1, definition2), new Secrets(emptyList())))
                .hasMessageContaining("aaaaa' of the secret exceeds the maximum length of 22 characters")
                .hasMessageContaining("bbbbb' of the secret exceeds the maximum length of 22 characters");
    }

    @Test
    @DisplayName("When using PRD Vault and secret is for team environment then NO secret should be generated")
    void prdTeamEnvironment() {
        var definition = SecretDefinition.builder()
                .name("aa")
                .description("a test secret")
                .projectName("test-project")
                .gitlabRepoNamespace("test-namespace")
                .rotate(true)
                .plaintextSecret(Base64String.encode("mysecret"))
                .secretType(SecretType.KEY_128)
                .environments(allEnvironments().findEnvironments("team4", "team9"))
                .build();
        var projectSecretsGenerator = new ProjectSecretsGenerator(secretDefinitionGenerator, generator, new Options(true, true, "Test MR"));

        var secrets = projectSecretsGenerator.update(Set.of(definition), new Secrets(emptyList()));

        assertThat(secrets.getYoltSecrets()).isEmpty();
    }

    @Test
    @DisplayName("When using DTA Vault and secret is for PRD environment then NO secret should be generated")
    void dtaPRDEnvironment() {
        var definition = SecretDefinition.builder()
                .name("aa")
                .description("a test secret")
                .projectName("test-project")
                .gitlabRepoNamespace("test-namespace")
                .rotate(true)
                .plaintextSecret(Base64String.encode("mysecret"))
                .secretType(SecretType.KEY_128)
                .environments(allEnvironments().findEnvironments("yfb-prd", "yfb-sandbox"))
                .build();
        var projectSecretsGenerator = new ProjectSecretsGenerator(secretDefinitionGenerator, generator, new Options(true, false, "Test MR"));

        var secrets = projectSecretsGenerator.update(Set.of(definition), new Secrets(emptyList()));

        assertThat(secrets.getYoltSecrets()).isEmpty();
    }

    @Test
    @DisplayName("Given multiple existing secrets for different environments when adding a new secret for only two environments then it should only return those environments with all secrets")
    void multipleEnvs() {
        Secret team4 = Secret.builder().secretType(CERT_ANY_IMPORT).secretName("test").vaultPath("team4-ycs-stubs").environment(findEnvironments("team4", Namespace.YCS)).build();
        Secret yfbSandbox = Secret.builder().secretType(CERT_ANY_IMPORT).secretName("test").vaultPath("yfb-sandbox-ycs-stubs").environment(findEnvironments("yfb-sandbox", Namespace.YCS)).build();
        Secret yfbPrd = Secret.builder().secretType(CERT_ANY_IMPORT).secretName("test").vaultPath("yfb-prd-ycs-stubs").environment(findEnvironments("yfb-prd", Namespace.YCS)).build();
        var secrets = new Secrets(List.of(team4, yfbSandbox, yfbPrd));
        var newDefinition = SecretDefinition.builder()
                .name("new_secret")
                .description("a test secret")
                .projectName("stubs")
                .gitlabRepoNamespace("test-namespace")
                .plaintextSecret(Base64String.encode("mysecret"))
                .secretType(SecretType.KEY_128)
                .environments(allEnvironments().findEnvironments("yfb-prd", "yfb-sandbox"))
                .build();
        var projectSecretsGenerator = new ProjectSecretsGenerator(secretDefinitionGenerator, generator, new Options(true, true, "Test MR"));

        var updatedSecrets = projectSecretsGenerator.update(Set.of(newDefinition), secrets);

        assertThat(updatedSecrets.getYoltSecrets()).hasSize(4);
        assertThat(updatedSecrets.getYoltSecrets()).extracting(Secret::getVaultPath).containsAnyOf("yfb-prd-ycs-stubs", "yfb-sandbox-ycs-stubs");
    }

    @Test
    @DisplayName("Given multiple existing secrets for different environments when adding a new secret for only one environments then it should only return that environment with all secrets")
    void multipleEnvsUpdating() {
        Secret team4 = Secret.builder().secretType(CERT_ANY_IMPORT).secretName("test").vaultPath("team4-ycs-stubs").environment(findEnvironments("team4", Namespace.YCS)).build();
        Secret yfbSandbox = Secret.builder().secretType(CERT_ANY_IMPORT).secretName("test").vaultPath("yfb-sandbox-ycs-stubs").environment(findEnvironments("yfb-sandbox", Namespace.YCS)).build();
        Secret yfbPrd = Secret.builder().secretType(CERT_ANY_IMPORT).secretName("test").vaultPath("yfb-prd-ycs-stubs").environment(findEnvironments("yfb-prd", Namespace.YCS)).build();
        var secrets = new Secrets(List.of(team4, yfbSandbox, yfbPrd));
        var newDefinition = SecretDefinition.builder()
                .name("new_secret")
                .description("a test secret")
                .projectName("stubs")
                .gitlabRepoNamespace("test-namespace")
                .plaintextSecret(Base64String.encode("mysecret"))
                .secretType(SecretType.KEY_128)
                .environments(allEnvironments().findEnvironments("team4"))
                .build();
        var projectSecretsGenerator = new ProjectSecretsGenerator(secretDefinitionGenerator, generator, new Options(true, false, "Test MR"));

        var updatedSecrets = projectSecretsGenerator.update(Set.of(newDefinition), secrets);

        assertThat(updatedSecrets.getYoltSecrets()).hasSize(2);
        assertThat(updatedSecrets.getYoltSecrets()).extracting(Secret::getVaultPath).containsAnyOf("team4-ycs-stubs");
    }

    private Environment findEnvironments(String name, Namespace namespace) {
        var allEnvironments = Environments.AllEnvironments.allEnvironments();
        return allEnvironments.getAllEnvironments().stream().filter(env -> env.getName().equals(name) && env.getNamespace() == namespace).findFirst().orElseThrow();
    }

    @Test
    @DisplayName("Given multiple existing secrets for different DTA environments when adding a new secret for only one environments then it should only return that environment with all secrets")
    void multipleDTAEnvs() {
        Secret team4 = Secret.builder().secretType(CERT_ANY_IMPORT).secretName("test").vaultPath("team4-ycs-stubs").environment(findEnvironments("team4", Namespace.YCS)).build();
        Secret team5 = Secret.builder().secretType(CERT_ANY_IMPORT).secretName("test").vaultPath("team5-ycs-stubs").environment(findEnvironments("team5", Namespace.YCS)).build();
        Secret team6 = Secret.builder().secretType(CERT_ANY_IMPORT).secretName("test").vaultPath("team6-ycs-stubs").environment(findEnvironments("team6", Namespace.YCS)).build();
        var secrets = new Secrets(List.of(team4, team5, team6));
        var newDefinition = SecretDefinition.builder()
                .name("new_secret")
                .description("a test secret")
                .projectName("stubs")
                .gitlabRepoNamespace("test-namespace")
                .plaintextSecret(Base64String.encode("mysecret"))
                .secretType(SecretType.KEY_128)
                .environments(allEnvironments().findEnvironments("team4"))
                .build();
        var projectSecretsGenerator = new ProjectSecretsGenerator(secretDefinitionGenerator, generator, new Options(true, false, "Test MR"));

        var updatedSecrets = projectSecretsGenerator.update(Set.of(newDefinition), secrets);

        assertThat(updatedSecrets.getYoltSecrets()).hasSize(2);
        assertThat(updatedSecrets.getYoltSecrets()).extracting(Secret::getVaultPath).containsAnyOf("team4-ycs-stubs");
    }

    @Test
    @DisplayName("Given multiple existing secrets for different environments when adding a new secret for a team environment with a PRD Vault then it should return nothing")
    void teamEnvWithPRDRunner() {
        Secret team4 = Secret.builder().secretType(CERT_ANY_IMPORT).secretName("test").vaultPath("team4-ycs-stubs").environment(findEnvironments("team4", Namespace.YCS)).build();
        Secret yfbSandbox = Secret.builder().secretType(CERT_ANY_IMPORT).secretName("test").vaultPath("yfb-sandbox-ycs-stubs").environment(findEnvironments("yfb-sandbox", Namespace.YCS)).build();
        Secret yfbPrd = Secret.builder().secretType(CERT_ANY_IMPORT).secretName("test").vaultPath("yfb-prd-default-stubs").environment(findEnvironments("yfb-prd", Namespace.YCS)).build();
        var secrets = new Secrets(List.of(team4, yfbSandbox, yfbPrd));
        var newDefinition = SecretDefinition.builder()
                .name("new_secret")
                .description("a test secret")
                .projectName("test-project")
                .gitlabRepoNamespace("backend")
                .plaintextSecret(Base64String.encode("mysecret"))
                .secretType(SecretType.KEY_128)
                .environments(allEnvironments().findEnvironments("team4"))
                .build();
        var projectSecretsGenerator = new ProjectSecretsGenerator(secretDefinitionGenerator, generator, new Options(true, true, "Test MR"));

        var updatedSecrets = projectSecretsGenerator.update(Set.of(newDefinition), secrets);

        assertThat(updatedSecrets.getYoltSecrets()).isEmpty();
    }
}