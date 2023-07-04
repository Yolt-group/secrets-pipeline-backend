package com.yolt.secretspipeline;

import com.yolt.secretspipeline.secrets.Base64String;
import com.yolt.secretspipeline.secrets.Secret;
import com.yolt.secretspipeline.secrets.Secrets;
import com.yolt.secretspipeline.secrets.VaultString;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static com.yolt.secretspipeline.secrets.Environments.AllEnvironments.allEnvironments;
import static com.yolt.secretspipeline.secrets.Environments.Namespace.YCS;
import static com.yolt.secretspipeline.secrets.SecretType.CERT_ANY_IMPORT;
import static org.assertj.core.api.Assertions.assertThat;

class SecretsTest {

    @Test
    void noExistingShouldAddNew() {
        Secrets existingSecret = new Secrets(new ArrayList<>());
        Secret newSecret = Secret.builder()
                .secretType(CERT_ANY_IMPORT)
                .secretName("test")
                .vaultPath("team5-ycs-stubs")
                .environment(allEnvironments().findEnvironments("team5", YCS).getAllEnvironments().stream().findFirst().orElseThrow())
                .build();

        existingSecret.upsert(newSecret);

        assertThat(existingSecret.contains(newSecret)).isTrue();
    }

    @Test
    void newSecretShouldBeAddedAtTheEnd() {
        Secret existingSecret = Secret.builder()
                .secretType(CERT_ANY_IMPORT)
                .secretName("test")
                .vaultPath("team5-ycs-stubs")
                .environment(allEnvironments().findEnvironments("team5", YCS).getAllEnvironments().stream().findFirst().orElseThrow())
                .build();
        Secrets existing = new Secrets(List.of(existingSecret));
        Secret newSecret = Secret.builder()
                .secretType(CERT_ANY_IMPORT)
                .secretName("new")
                .vaultPath("team5-ycs-stubs")
                .environment(allEnvironments().findEnvironments("team5", YCS).getAllEnvironments().stream().findFirst().orElseThrow())
                .build();

        existing.upsert(newSecret);

        assertThat(existing.getYoltSecrets().indexOf(newSecret)).isEqualTo(1);
    }

    @Test
    void shouldUpdateSecretIfRotateIsTrue() {
        Secret existingSecret = Secret.builder()
                .secretType(CERT_ANY_IMPORT)
                .secretName("test")
                .rotate(true)
                .vaultPath("team5-YCS-stubs")
                .environment(allEnvironments().findEnvironments("team5", YCS).getAllEnvironments().stream().findFirst().orElseThrow())
                .build();
        Secrets existing = new Secrets(List.of(existingSecret));
        Secret newSecret = Secret.builder()
                .secretType(CERT_ANY_IMPORT)
                .secretName("test")
                .content(VaultString.from("vault:v1:" + Base64String.encode("new content")))
                .rotate(true)
                .vaultPath("team5-YCS-stubs")
                .environment(allEnvironments().findEnvironments("team5", YCS).getAllEnvironments().stream().findFirst().orElseThrow())
                .build();

        existing.upsert(newSecret);

        assertThat(existing.size()).isEqualTo(1);
        assertThat(existing.find(newSecret).orElseThrow().content).isEqualTo(VaultString.from("vault:v1:bmV3IGNvbnRlbnQ="));
    }

    @Test
    void shouldNotUpdateSecretIfRotateIsFalse() {
        Secret existingSecret = Secret.builder()
                .secretType(CERT_ANY_IMPORT)
                .secretName("test")
                .vaultPath("team5-ycs-stubs")
                .environment(allEnvironments().findEnvironments("team5", YCS).getAllEnvironments().stream().findFirst().orElseThrow())
                .build();
        Secrets existing = new Secrets(List.of(existingSecret));
        Secret newSecret = Secret.builder()
                .secretType(CERT_ANY_IMPORT)
                .secretName("test")
                .content(VaultString.from("vault:v1:" + Base64String.encode("new content")))
                .rotate(false)
                .vaultPath("team5-ycs-stubs")
                .environment(allEnvironments().findEnvironments("team5", YCS).getAllEnvironments().stream().findFirst().orElseThrow())
                .build();

        existing.upsert(newSecret);

        assertThat(existing.size()).isEqualTo(1);
        assertThat(existing.find(newSecret).orElseThrow().content).isNull();
    }
}