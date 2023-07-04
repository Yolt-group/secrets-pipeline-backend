package com.yolt.secretspipeline.command.io.writers;

import com.yolt.secretspipeline.command.io.FileContents;
import com.yolt.secretspipeline.secrets.Base64String;
import com.yolt.secretspipeline.secrets.Secret;
import com.yolt.secretspipeline.secrets.SecretType;
import com.yolt.secretspipeline.secrets.Secrets;
import com.yolt.secretspipeline.secrets.VaultString;
import org.assertj.core.api.Condition;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static com.yolt.secretspipeline.generators.SecretsGeneratorTest.POD_CERT;
import static com.yolt.secretspipeline.secrets.Environments.AllEnvironments.allEnvironments;
import static com.yolt.secretspipeline.secrets.Environments.Namespace.YCS;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
public class KustomizeSecretsWriterTest {

    @Test
    @DisplayName("When generating GPG (no pair) it should not add the public part")
    void gpgDoesNotHavePublicPart() {
        var secret = Secret.builder()
                .secretType(SecretType.GPG)
                .secretName("test")
                .vaultPath("team4-ycs")
                .environment(allEnvironments().findEnvironments("team4", YCS).getAllEnvironments().stream().findFirst().orElseThrow())
                .content(VaultString.from("vault:v1:sdfasdf"))
                .build();
        var writer = new KustomizeSecretsWriter("test");
        var expectedContent = """
                apiVersion: apps/v1
                kind: Deployment
                metadata:
                  name: test
                spec:
                  template:
                    metadata:
                      annotations:
                        vault.hashicorp.com/agent-inject-secret-test: ""
                        vault.hashicorp.com/agent-inject-template-test: |
                          {{- with secret "transit/git/decrypt/team4-ycs" "ciphertext=vault:v1:sdfasdf" "context=eW9sdC1naXQtc3RvcmFnZQo=" -}}
                          type: GPG
                          {{ .Data.plaintext }}
                          {{- end -}}
                """;

        var files = writer.writeSecrets(new Secrets(List.of(secret)));

        assertThat(files).contains(new FileContents("k8s/env/dta/team4/cluster2/ycs/secrets-pipeline.yml", Base64String.encode(expectedContent)));
    }

    private Condition<Base64String> contains(String expected) {
        return new Condition<>() {
            public boolean matches(Base64String contents) {
                return contents.decode().contains(expected);
            }
        };
    }

    @Test
    @DisplayName("When generating a GPG pair it should also add the public part")
    void gpgPairDoesHavePublicPart() {
        var secret = Secret.builder()
                .secretType(SecretType.GPG_PAIR)
                .secretName("test")
                .vaultPath("team4-ycs")
                .environment(allEnvironments().findEnvironments("team4", YCS).getAllEnvironments().stream().findFirst().orElseThrow())
                .publicKeyOrCertContent(Base64String.of("dGVzdAo="))
                .content(VaultString.from("vault:v1:sdfasdf"))
                .build();
        var writer = new KustomizeSecretsWriter("test");
        var files = writer.writeSecrets(new Secrets(List.of(secret)));

        assertThat(files)
                .first()
                .extracting(FileContents::getContents)
                .has(contains("----------"))
                .has(contains("dGVzdAo="));
    }

    @Test
    @DisplayName("When writing secrets twice then the order should be the same")
    void writingTwiceShouldHaveSameOrder() {
        var secret1 = Secret.builder()
                .secretType(SecretType.GPG_PAIR)
                .secretName("test")
                .vaultPath("team9-ycs")
                .environment(allEnvironments().findEnvironments("team9", YCS).getAllEnvironments().stream().findFirst().orElseThrow())
                .publicKeyOrCertContent(Base64String.of("dGVzdAo="))
                .content(VaultString.from("vault:v1:sdfasdf"))
                .build();
        var secret2 = secret1.toBuilder()
                .vaultPath("team4-ycs")
                .environment(allEnvironments().findEnvironments("team4", YCS).getAllEnvironments().stream().findFirst().orElseThrow())
                .build();
        var writer = new KustomizeSecretsWriter("test");

        var files1 = writer.writeSecrets(new Secrets(List.of(secret1, secret2)));
        var files2 = writer.writeSecrets(new Secrets(List.of(secret1, secret2)));

        assertThat(files1).containsExactlyElementsOf(files2);
    }
}
