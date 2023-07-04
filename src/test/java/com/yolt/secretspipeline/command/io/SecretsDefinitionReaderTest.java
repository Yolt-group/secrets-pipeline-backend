package com.yolt.secretspipeline.command.io;

import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.yolt.secretspipeline.command.GitlabApiWrapper;
import com.yolt.secretspipeline.command.io.readers.SecretsDefinitionReader;
import com.yolt.secretspipeline.secrets.Base64String;
import com.yolt.secretspipeline.secrets.Environments;
import com.yolt.secretspipeline.secrets.SecretType;
import com.yolt.secretspipeline.secrets.UnixEpoch;
import com.yolt.secretspipeline.secrets.VaultString;
import com.yolt.secretspipeline.secrets.templates.CSRTemplate;
import com.yolt.secretspipeline.secrets.templates.JWKSTemplate;
import com.yolt.secretspipeline.secrets.templates.PGPTemplate;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.util.ResourceUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static com.yolt.secretspipeline.command.SecretsPipelineApplicationRunner.SECRETS_PIPELINE_PROJECT_ID;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;
import static org.springframework.util.Base64Utils.encodeToString;

@ExtendWith(MockitoExtension.class)
class SecretsDefinitionReaderTest {

    @Mock
    private GitlabApiWrapper gitlab;

    @Test
    @DisplayName("Reading definition from Gitlab should pass")
    void read() throws IOException {
        var fileContents = Files.readString(ResourceUtils.getFile("classpath:security/secretdefinition.json").toPath());
        when(gitlab.getFile(SECRETS_PIPELINE_PROJECT_ID, "banking.json", "master")).thenReturn(Optional.of(encodeToString(fileContents.getBytes(UTF_8))));

        var definitions = new SecretsDefinitionReader(gitlab).readSecretsDefinitions(List.of("banking.json"), "master");

        assertThat(definitions).hasSize(3);
    }

    @Test
    @DisplayName("Given secret definition is a separate file called github.json when the secrets are read then the project name should be correct")
    void projectName() throws IOException {
        var fileContents = Files.readString(ResourceUtils.getFile("classpath:security/secretdefinition.json").toPath());
        when(gitlab.getFile(SECRETS_PIPELINE_PROJECT_ID, "yts-credit-scoring-app/github.json", "master")).thenReturn(Optional.of(encodeToString(fileContents.getBytes(UTF_8))));

        var definitions = new SecretsDefinitionReader(gitlab).readSecretsDefinitions(List.of("yts-credit-scoring-app/github.json"), "master");

        assertThat(definitions).hasSize(3);
        assertThat(definitions).extracting(s -> s.projectName).allMatch("yts-credit-scoring-app"::equals);
    }

    @Test
    @DisplayName("When Gitlab does not return a file reading secret definitions should fail")
    void fileNotPresent() {
        SecretsDefinitionReader secretsDefinitionReader = new SecretsDefinitionReader(gitlab);

        assertThatThrownBy(() -> secretsDefinitionReader.readSecretsDefinitions(List.of("banking.json"), "master"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("When the definition is not correct then reading should fail")
    void readIncomplete() throws IOException {
        var fileContents = Files.readString(ResourceUtils.getFile("classpath:security/incomplete_secretdefinition.json").toPath());
        when(gitlab.getFile(SECRETS_PIPELINE_PROJECT_ID, "banking.json", "master")).thenReturn(Optional.of(encodeToString(fileContents.getBytes(UTF_8))));

        assertThatThrownBy(() -> new SecretsDefinitionReader(gitlab).readSecretsDefinitions(List.of("banking.json"), "master"))
                .isInstanceOf(MismatchedInputException.class);
    }

    @Test
    @DisplayName("When a JSON file is read then all fields should be correctly populated")
    void json() throws IOException {
        var fileContents = Files.readString(ResourceUtils.getFile("classpath:security/read_json_definition.json").toPath());
        when(gitlab.getFile(SECRETS_PIPELINE_PROJECT_ID, "yts-credit-scoring-app/github.json", "master")).thenReturn(Optional.of(encodeToString(fileContents.getBytes(UTF_8))));

        var definitions = new SecretsDefinitionReader(gitlab).readSecretsDefinitions(List.of("yts-credit-scoring-app/github.json"), "master");

        Assertions.assertThat(definitions)
                .hasSize(1)
                .first()
                .hasFieldOrPropertyWithValue("name", "Stubs example key")
                .hasFieldOrPropertyWithValue("secretType", SecretType.KEY_128)
                .hasFieldOrPropertyWithValue("description", "Example key for stubs")
                .hasFieldOrPropertyWithValue("gitlabRepoNamespace", "backend")
                .hasFieldOrPropertyWithValue("environments", Environments.AllEnvironments.allEnvironments().findEnvironments("team5", "yfb-acc"))
                .hasFieldOrPropertyWithValue("rotate", true)
                .hasFieldOrPropertyWithValue("publicKeyOrCert", Base64String.of("test"))
                .hasFieldOrPropertyWithValue("importedSecret", VaultString.from("vault:v1:dmF1bHRlbmNyeXB0ZWRzdHVmZmhlcmUK"))
                .hasFieldOrPropertyWithValue("validTilUnixEpoch", new UnixEpoch(1893456000L))
                .hasFieldOrPropertyWithValue("projectName", "yts-credit-scoring-app")
                .hasFieldOrPropertyWithValue("skipPasswordLengthValidation", true)
                .hasFieldOrPropertyWithValue("plaintextSecret", null)
                .hasFieldOrPropertyWithValue("pgpTemplate", new PGPTemplate("security@yolt.io.test", 2048, 2, 0L, null, null, null, 3))
                .hasFieldOrPropertyWithValue("jwksTemplate", new JWKSTemplate("PS512", "sig", "RSA", 2048, "123"))
                .hasFieldOrPropertyWithValue("csrTemplate",
                        new CSRTemplate(
                                "CN=kvk.team5.yolt.io",
                                4096,
                                "SHA256withRSA",
                                Set.of("digitalSignature", "nonRepudiation"),
                                Set.of("serverAuth", "clientAuth"),
                                List.of("kvk.team5.yolt.io")
                        )
                );
    }
}