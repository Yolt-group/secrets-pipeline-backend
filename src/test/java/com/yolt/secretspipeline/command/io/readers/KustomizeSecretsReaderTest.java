package com.yolt.secretspipeline.command.io.readers;

import com.yolt.secretspipeline.command.GitlabApiWrapper;
import com.yolt.secretspipeline.secrets.Base64String;
import com.yolt.secretspipeline.secrets.Environment;
import com.yolt.secretspipeline.secrets.Secret;
import com.yolt.secretspipeline.secrets.SecretType;
import com.yolt.secretspipeline.secrets.VaultString;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.util.ResourceUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.Optional;

import static com.yolt.secretspipeline.secrets.Environments.AllEnvironments.allEnvironments;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KustomizeSecretsReaderTest {

    private final String contents = Base64String.encode("""
                     apiVersion: apps/v1
                     kind: Deployment
                     metadata:
                       name: banking
                     spec:
                       template:
                         metadata:
                           annotations:
                             vault.hashicorp.com/agent-inject-secret-orian-token: ""
                             vault.hashicorp.com/agent-inject-secret-payvision-password: ""
                             vault.hashicorp.com/agent-inject-secret-pps-master-account: ""
                             vault.hashicorp.com/agent-inject-secret-pps-password: ""
                             vault.hashicorp.com/agent-inject-secret-pps-shared-secret: ""
                             vault.hashicorp.com/agent-inject-template-orian-token: |
                               {{- with secret "transit/git/decrypt/team9-ycs-site-management" "ciphertext=vault:v1:dGVzdAo=" "context=eW9sdC1naXQtc3RvcmFnZQo=" -}}
                               type: PASSWORD_ALFA_NUMERIC
                               {{ .Data.plaintext }}
                               {{- end -}}
                             vault.hashicorp.com/agent-inject-template-api-gw-req-jwks: |
                               {{- with secret "transit/git/decrypt/team6-ycs-client-gateway" "ciphertext=vault:v1:dGVzdAo=" "context=eW9sdC1naXQtc3RvcmFnZQo=" -}}
                               type: JWKS
                               {{ .Data.plaintext }}
                               ----------
                               dGVzdAo=
                               {{- end -}}
                             vault.hashicorp.com/agent-inject-template-evidence_certificate: |
                               {{- with secret "transit/git/decrypt/yfb-acc-ycs-site-management" "ciphertext=vault:v1:dGVzdAo=" "context=eW9sdC1naXQtc3RvcmFnZQo=" -}}
                               type: GPG
                               {{ .Data.plaintext }}
                               {{- end -}}
                             vault.hashicorp.com/agent-inject-template-private-key-acc2.asc: |
                               {{- with secret "transit/git/decrypt/yfb-acc-ycs-site-management" "ciphertext=vault:v1:dGVzdAo=" "context=eW9sdC1naXQtc3RvcmFnZQo=" -}}
                               type: GPG_PAIR
                               {{ .Data.plaintext }}
                               ----------
                               dGVzdAo=
                               {{- end -}}
                             vault.hashicorp.com/agent-inject-template-safened_clientId: |
                               {{- with secret "transit/git/decrypt/yfb-acc-ycs-site-management" "ciphertext=vault:v1:1OW/7wnAOdaqD5IUg6+zknxFFUkAnisd54joKKOozAkITzQ/sywh8RcyxvfoQGPz" "context=eW9sdC1naXQtc3RvcmFnZQo=" -}}
                               type: PASSWORD_ALFA_NUMERIC
                               {{ .Data.plaintext }}
                               {{- end -}}
                             vault.hashicorp.com/agent-inject-template-safened_clientSecret: |
                               {{- with secret "transit/git/decrypt/yfb-acc-ycs-site-management" "ciphertext=vault:v1:/gwm31sitvhlFG9Cqnd6amemieRvFabTS3G0RT9lKFs45zqWGdNSPkE1fzo13XKSY2nURK0iNDkejVWl" "context=eW9sdC1naXQtc3RvcmFnZQo=" -}}
                               type: PASSWORD_ALFA_NUMERIC_SPECIAL_CHARS
                               {{ .Data.plaintext }}
                               {{- end -}}
                             vault.hashicorp.com/agent-inject-template-brazeEncryptionKey: |
                               {{- with secret "transit/git/decrypt/yfb-acc-ycs-providers" "ciphertext=vault:v1:gMphapvtQUfdCLxuepNFPrqEDGcWgeImhdm8yEdb8NkxmVlWnxWcXtZBrXo=" "context=eW9sdC1naXQtc3RvcmFnZQo=" -}}
                               type: KEY_128
                               {{ .Data.plaintext }}
                               {{- end -}}
                             vault.hashicorp.com/agent-inject-template-push.ios.cert.pwd: |
                               {{- with secret "transit/git/decrypt/yfb-acc-ycs-tokens" "ciphertext=vault:v1:6FK3gRyZeIiRCHx1f5DQDm5maq5bfStnY9Zrr/8pzmbtYCMkPmtmGUT56Q==" "context=eW9sdC1naXQtc3RvcmFnZQo=" -}}
                               type: PASSWORD_ALFA_NUMERIC_SPECIAL_CHARS
                               {{ .Data.plaintext }}
                               {{- end -}}
            """).toString();

    @Mock
    private GitlabApiWrapper gitlab;

    @BeforeEach
    void setup(){
        when(gitlab.getFile(any(), any(),any())).thenReturn(Optional.of(contents));
    }

    private Environment clusterZeroOf(String environment) {
        return allEnvironments()
                .findEnvironments(environment)
                .getAllEnvironments()
                .stream()
                .filter(environment1 -> environment1.getCluster().equals("cluster2"))
                .findFirst()
                .orElseThrow();
    }

    @Test
    @DisplayName("When a K8s file contains 'PASSWORD_ALFA_NUMERIC' then the reader should read them")
    void readSecretPassword() {
        var expectedSecret = Secret.builder()
                .secretName("orian-token")
                .environment(clusterZeroOf("team9"))
                .content(VaultString.from("vault:v1:dGVzdAo="))
                .secretType(SecretType.PASSWORD_ALFA_NUMERIC)
                .vaultPath("team9-ycs-site-management")
                .build();

        var secrets = new KustomizeSecretsReader(gitlab, allEnvironments()).readSecrets(10);
        assertThat(secrets.getYoltSecrets()).contains(expectedSecret);
    }

    @Test
    @DisplayName("When a K8s file contains 'JWKS' then the reader should read them")
    void readSecretJWKS() {
        var expectedSecret = Secret.builder()
                .secretName("api-gw-req-jwks")
                .environment(clusterZeroOf("team6"))
                .content(VaultString.from("vault:v1:dGVzdAo="))
                .secretType(SecretType.JWKS)
                .publicKeyOrCertContent(Base64String.of("dGVzdAo="))
                .vaultPath("team6-ycs-client-gateway")
                .build();

        var secrets = new KustomizeSecretsReader(gitlab, allEnvironments()).readSecrets(10);

        assertThat(secrets.getYoltSecrets()).contains(expectedSecret);
    }

    @Test
    @DisplayName("When a K8s file contains 'GPG' then the reader should read them")
    void readSecretGPG() {
        var expectedSecret = Secret.builder()
                .secretName("evidence_certificate")
                .environment(clusterZeroOf("yfb-acc"))
                .content(VaultString.from("vault:v1:dGVzdAo="))
                .secretType(SecretType.GPG)
                .vaultPath("yfb-acc-ycs-site-management")
                .build();

        var secrets = new KustomizeSecretsReader(gitlab, allEnvironments()).readSecrets(10);

        assertThat(secrets.getYoltSecrets()).contains(expectedSecret);
    }

    @Test
    @DisplayName("When a K8s file contains 'GPG_PAIR' then the reader should read them")
    void readSecretGPG_PAIR() {
        var expectedSecret = Secret.builder()
                .secretName("private-key-acc2.asc")
                .environment(clusterZeroOf("yfb-acc"))
                .content(VaultString.from("vault:v1:dGVzdAo="))
                .publicKeyOrCertContent(Base64String.of("dGVzdAo="))
                .secretType(SecretType.GPG_PAIR)
                .vaultPath("yfb-acc-ycs-site-management")
                .build();

        var secrets = new KustomizeSecretsReader(gitlab, allEnvironments()).readSecrets(10);

        assertThat(secrets.getYoltSecrets()).contains(expectedSecret);
    }

    @Test
    @DisplayName("When a K8s file contains 'PASSWORD_ALFA_NUMERIC' then the reader should read them")
    void readSecretPASSWORD_ALFA_NUMERIC() {
        var expectedSecret = Secret.builder()
                .secretName("safened_clientId")
                .environment(clusterZeroOf("yfb-acc"))
                .content(VaultString.from("vault:v1:1OW/7wnAOdaqD5IUg6+zknxFFUkAnisd54joKKOozAkITzQ/sywh8RcyxvfoQGPz"))
                .secretType(SecretType.PASSWORD_ALFA_NUMERIC)
                .vaultPath("yfb-acc-ycs-site-management")
                .build();

        var secrets = new KustomizeSecretsReader(gitlab, allEnvironments()).readSecrets(10);

        assertThat(secrets.getYoltSecrets()).contains(expectedSecret);
    }

    @Test
    @DisplayName("When a K8s file contains 'PASSWORD_ALFA_NUMERIC_SPECIAL_CHARS' then the reader should read them")
    void readSecretPASSWORD_ALFA_NUMERIC_SPECIAL_CHARS() {
        var expectedSecret = Secret.builder()
                .secretName("safened_clientSecret")
                .environment(clusterZeroOf("yfb-acc"))
                .content(VaultString.from("vault:v1:/gwm31sitvhlFG9Cqnd6amemieRvFabTS3G0RT9lKFs45zqWGdNSPkE1fzo13XKSY2nURK0iNDkejVWl"))
                .secretType(SecretType.PASSWORD_ALFA_NUMERIC_SPECIAL_CHARS)
                .vaultPath("yfb-acc-ycs-site-management")
                .build();

        var secrets = new KustomizeSecretsReader(gitlab, allEnvironments()).readSecrets(10);

        assertThat(secrets.getYoltSecrets()).contains(expectedSecret);
    }

    @Test
    @DisplayName("When a K8s file contains 'KEY_128' then the reader should read them")
    void readSecretKEY_128() {
        var expectedSecret = Secret.builder()
                .secretName("brazeEncryptionKey")
                .environment(clusterZeroOf("yfb-acc"))
                .content(VaultString.from("vault:v1:gMphapvtQUfdCLxuepNFPrqEDGcWgeImhdm8yEdb8NkxmVlWnxWcXtZBrXo="))
                .secretType(SecretType.KEY_128)
                .vaultPath("yfb-acc-ycs-providers")
                .build();

        var secrets = new KustomizeSecretsReader(gitlab, allEnvironments()).readSecrets(10);

        assertThat(secrets.getYoltSecrets()).contains(expectedSecret);
    }

    @Test
    @DisplayName("When a K8s file contains 'PASSWORD_ALFA_NUMERIC_SPECIAL_CHARS' with special chars in name then the reader should read them")
    void readSecret_PASSWORD_ALFA_NUMERIC_SPECIAL_CHARS() {
        var expectedSecret = Secret.builder()
                .secretName("push.ios.cert.pwd")
                .environment(clusterZeroOf("yfb-acc"))
                .content(VaultString.from("vault:v1:6FK3gRyZeIiRCHx1f5DQDm5maq5bfStnY9Zrr/8pzmbtYCMkPmtmGUT56Q=="))
                .secretType(SecretType.PASSWORD_ALFA_NUMERIC_SPECIAL_CHARS)
                .vaultPath("yfb-acc-ycs-tokens")
                .build();

        var secrets = new KustomizeSecretsReader(gitlab, allEnvironments()).readSecrets(10);

        assertThat(secrets.getYoltSecrets()).contains(expectedSecret);
    }

    @Test
    @DisplayName("Given multiple environments when reading the secrets then all secrets are returned for all environments")
    void readMultipleEnvironmentsSecretsCluster() {
        when(gitlab.getFile(any(),any(), any())).then(invocationOnMock -> {
            String file = invocationOnMock.getArgument(1, String.class);
            try {
                var contents = Files.readString(ResourceUtils.getFile("classpath:multiple_environments/" + file).toPath());
                return Optional.of(Base64String.encode(contents).toString());
            } catch (IOException e) {
                return Optional.empty();
            }
        });
        var secrets = new KustomizeSecretsReader(gitlab, allEnvironments()).readSecrets(10);

        assertThat(secrets.getYoltSecrets()).hasSize(16);
        assertThat(secrets.groupByEnvironment()).hasSize(2);
    }

}