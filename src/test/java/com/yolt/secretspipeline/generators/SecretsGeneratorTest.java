package com.yolt.secretspipeline.generators;

import com.yolt.secretspipeline.secrets.Base64String;
import com.yolt.secretspipeline.secrets.Secret;
import com.yolt.secretspipeline.secrets.SecretDefinition;
import com.yolt.secretspipeline.secrets.SecretType;
import com.yolt.secretspipeline.secrets.VaultString;
import com.yolt.secretspipeline.vaultrunner.VaultRunnerHelper;
import com.yolt.securityutils.crypto.PublicKey;
import com.yolt.securityutils.crypto.SecretKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collection;
import java.util.Set;

import static com.yolt.secretspipeline.secrets.Environments.AllEnvironments.allEnvironments;
import static java.util.Base64.getEncoder;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class SecretsGeneratorTest {

    public static final String POD_CERT = """
            -----BEGIN CERTIFICATE-----
            MIIEbzCCA1egAwIBAgIUNCtsvO5DKNu1DpAAFHGgx8CzyIEwDQYJKoZIhvcNAQEL
            BQAwEjEQMA4GA1UEAxMHZGVmYXVsdDAeFw0yMDAzMTIxMDQzMTVaFw0yMTAzMTIx
            MDQ0MTVaMEcxCzAJBgNVBAYTAk5MMRYwFAYDVQQIEw1Ob29yZC1Ib2xsYW5kMQ0w
            CwYDVQQKEwRZb2x0MREwDwYDVQQDEwhwYXJ0bmVyczCCASIwDQYJKoZIhvcNAQEB
            BQADggEPADCCAQoCggEBALNOfSHbInlcT2qA/OcNzo5Ey67/BGssNKnCvceolIcz
            dB/dCE2Ohwo+qjbrM0EjVEEF/Kn2FxfGSErdF3+Q0UJy8cqmgxJaUjVxIRmorQpI
            o6TxQifQwzO0toT7KM0GQ7G9CVNhU0wMYEW3M0in092BwEbXsYyYVY14SejyGE1p
            5zs01MVwH1SP9T8bN/xPl1MzUrylsC+48+EO8pfai2/nJpr3ZY8+XMEqjfn6K88J
            dInCC/Psaw08R1tMNQJ1k9rfhqs2jl2c9LLzOdQO+l4QXO5JIr9h3ECOWqgO6zlV
            M6FSQUfiuok/lKE9qPZcsQBbbmZzKYDlKB9AMrQqf2kCAwEAAaOCAYYwggGCMA4G
            A1UdDwEB/wQEAwIDqDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQU7iRN
            erQkYHsW8x0BH9M2+w+7VMEwHwYDVR0jBBgwFoAUZXdr3wTewBV2J5WNgPplzrfH
            hA8wgbAGCCsGAQUFBwEBBIGjMIGgME8GCCsGAQUFBzABhkNodHRwczovL3ZhdWx0
            LnZhdWx0LWR0YS55b2x0LmlvL3YxL3RlYW0xMC9rOHMvcG9kcy9kZWZhdWx0L3Br
            aS9vY3NwME0GCCsGAQUFBzAChkFodHRwczovL3ZhdWx0LnZhdWx0LWR0YS55b2x0
            LmlvL3YxL3RlYW0xMC9rOHMvcG9kcy9kZWZhdWx0L3BraS9jYTATBgNVHREEDDAK
            gghwYXJ0bmVyczBTBgNVHR8ETDBKMEigRqBEhkJodHRwczovL3ZhdWx0LnZhdWx0
            LWR0YS55b2x0LmlvL3YxL3RlYW0xMC9rOHMvcG9kcy9kZWZhdWx0L3BraS9jcmww
            DQYJKoZIhvcNAQELBQADggEBAFOm6VUGlIvSopGfXLvaT5hFsnnfmgexNHg6e7gU
            zn3Tif3C+EHZu6wwE/8blQJk8z4DdsfWC331fVyb18D4sq7f6La2TxeE3qwjm4Co
            37TU8v7BORDYnDTBxsb2DEm1LiwLceoAe8hdayGzsuOmZuK5HvhRO/vDhDX0LZVu
            Q2//u+7/J5kwDJbeDjoHzqO0QSGMT0HqTjhZlGDSnhxZYMf0M+7fDIqfcsytpbHt
            PhXW6I5s2Wv3t5safYJBYwk77uVt9DatdUXhIU5NiJMyuMttWpzJpzLj2+3tgXlm
            LZpWQ4w9Lh4GAkqsgJxjPjJgzd4jQKtCTl878bqyeoep6iA=
            -----END CERTIFICATE-----""";

    public static final String PRIVATE_KEY = """
            -----BEGIN RSA PRIVATE KEY-----
            MIIEowIBAAKCAQEAu/xm9hoWFdNQ0zbUKgdfcL/VJVJFlXYvPDIO1kKbv/x6/Wlk
            asWwabgtQ+yKky6C1xzlMJNs82kyPBwxF1jRqh73qeWAtudaCOYyCykCpkfgLbFe
            +Xd79g7hroKtcuF6TGREviWxCInwFFEHnf5TZTFypOUZHcWmEY7EGgeBXYBp40ZI
            5V9Jkid5kxTVygfJt/YbEf43S1j4iNAa2AWty2tN3W0n1DGwO6F8U4akiHcyrOjz
            dL2UejKdSdy8s1qCboW8Qhf8I6feFUmcOmM5ClfoWnZyeIlkqYAdrJhUFYkQsPgb
            i7oSi7HhQkBdWzt6ykoKw36WrHQ9tNqfwP/WFQIDAQABAoIBAAM+gNxgaN8pjWyH
            trOe+vOsK9aAC/lfV8NXLdBex+dRSSIUboo1LS0143oXm/CcTd++fOoQsUGmIBrP
            db1sZ/ninO2Oq2D8rx4WMujkZUpPVTwUoon1mOsPKK/lS27/Gyg0VsddSSfXkZAY
            MeR1HiVR7COSXJOZ9Jq69wFn/cCKTivlgPQrjEzwVXg/nrfzu+DKruloT2eGMJVX
            VtDlENUe7224gbvOoXTw457ZeNHvhPfTCCe9FDKFummeAq+kIXs53m7x6bscQ3Lj
            w05MyuiXWzN0W7N889l8qLuaEMKCsUfSaH/9tcw75HZBHsosePY8oAjvtXgUMPFx
            obuwrgUCgYEAxPuozDr7F1tMRAwPtIlX5wLb8uVxXel4Svl2dRJJ9PyItMuTCMK3
            c6QSbt9QJJP8P73gv7HVpLOYLvOBEq/OehaQ25FR6zDc7EaE1oj0q2N3lW7y8Nr9
            GJLdDn//86i4KFxaf6nRU88QXJKz2NJT3k2WwsIE3o0lFmZga8YiIccCgYEA9E6t
            XYDbJhuNBsSRBUhHzcOwERDirYIcaNsxxlBJBmdFKVTdo90byigd+kYEU0WpmTjS
            Vf3uEAHsYkM/wS4kVlpd+v0zd0CoabzW1fnXTi/7wlOB4vrhx80vWHO22hHyrkTX
            ezKq//AVBlmhjuFY+yqhHKVo4K/L3dNwqAYXCUMCgYBwLxL3HTAbITfSGTxoiT+y
            pQI21001Ot3zdRdtnTjZeWkx7i6S8rIf/fUxh6TQ8Cbc9nqlMdaGsnGda7i6t71T
            8r4VDjIlS/LF7XOB6wXNBhz40fMyEMXL1PhoZaWTUydudQplYoWAwZCD6FjcxwxU
            ssOFr5GuXZwdobiQKIsPyQKBgAVO8FVnx1s8ngPXoY8L0wOVjO3SABrlCNj+akZ0
            2CFbfRU40tgMpd3uoTge7Vkh2l2J7ogPzGxsnkZET85Swldd/0zE06lzrjUd9U0Q
            8KyyPjYqulfEO8Oroau6V+7FFRDUThpPL4gAH3TT3b7NBrHuazHEJlM7fqKDRZ9h
            An8hAoGBAKcAQkIfVTUUe/KEPEho7pvrLx1M2hNXuWB9v1j3fpsy91mggIysTFPP
            6Pc/+LyS/DMhgoF0KmlUkdzdcUe9ELcWPmerap6mYEtcSyBfRq9whth46E0zE22u
            JMYbxCd4QKDjU5Q+qj9OQjMqwqWguNGhapkT7/naOWqOl2SqpZpE
            -----END RSA PRIVATE KEY-----""";

    private static final String PUBLIC_KEY = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlSZZVQjXhGES83w2ly8+
            iVoOx3iJU/rkz5WW7aeFK0SChD2HwTE7g3PYR71/xUtzmEQI1/7ErJyG7u2Nxzdb
            E1ce7MEAqOLKP1CkfghjElbU/MkRCxNU6krkaJrtNM/Y80opWa30D5uP3GViZwEA
            jd7ow+dbDc+QHs1MplGnobL0kKuxve0+AmXlEJ5VLDIKT5spNyKp98ejzj1p7htT
            ltRK3LESGAmBGHL5fTQTbyyJe7HXGxpBJKB/IeVoAnlY8QzetilTuNZ1jkhGXCJJ
            NwM5Q6Cj9fPlGCXrLwHj7TxYpjdS9xyJYx5KZQpQ1TPJzpVqbhKYuwzP8ZZ2ZY2M
            AQIDAQAB
            -----END PUBLIC KEY-----""";

    public static final String PROJECTNAME = "stubs";
    public static final String REPO_PROJECT_NS = "backend";
    public static final String NAME = "testname";
    public static final String DESCRIPTION = "description";

    private final VaultRunnerHelper vaultRunnerHelper = mock(VaultRunnerHelper.class);
    private final SecretDefinitionGenerator secretDefinitionGenerator = new SecretDefinitionGenerator(vaultRunnerHelper);
    private final SecretsGenerator secretGenerator = new SecretsGenerator(vaultRunnerHelper);

    private static <T> T first(Collection<T> secretDefinitions) {
        return secretDefinitions.iterator().next();
    }

    @Test
    @DisplayName("Given a team environment with 1 namespace WHEN a secret is generated THEN only 1 secret should be generated")
    void oneNamespace() {
        when(vaultRunnerHelper.encryptSecret(any(), any())).thenReturn(VaultString.from("vault:v1:VE9fQkVfREVDUllQVEVEX0lOX1BJUEVMSU5FCg=="));
        var env = "team4";
        var definition = createSecretDefinition(env);
        definition = definition.toBuilder().secretType(SecretType.RSA_2048).build();

        var secrets = secretGenerator.secretDefinitionsToSecrets(secretDefinitionGenerator.extendWithRealSecret(Set.of(definition)));

        assertThat(secrets).hasSize(1);
    }

    @Test
    void rsaImport() {
        var env = "team5";
        when(vaultRunnerHelper.dtaDecryptImportedSecret(any())).thenReturn(Base64String.encode(PRIVATE_KEY));
        when(vaultRunnerHelper.encryptSecret(any(), any())).thenReturn(VaultString.from("vault:v1:VE9fQkVfREVDUllQVEVEX0lOX1BJUEVMSU5FCg=="));
        SecretDefinition definition = createSecretDefinition(env).toBuilder()
                .secretType(SecretType.RSA_2048)
                .publicKeyOrCert(Base64String.encode(PUBLIC_KEY))
                .importedSecret(VaultString.from("vault:v1:" + "ZW5jcnlwdGVkCg"))
                .build();
        var definitions = secretDefinitionGenerator.extendWithRealSecret(Set.of(definition));

        Set<Secret> secrets = secretGenerator.secretDefinitionsToSecrets(definitions);
        Secret secret = secrets.iterator().next();
        assertThat(secret.secretName).isEqualTo(definition.name);
        assertThat(secret.rotate).isEqualTo(definition.rotate);

        Base64String publicKeyMaterial = secret.publicKeyOrCertContent;
        PublicKey publicKey = PublicKey.createPublicKeyFromPem(publicKeyMaterial.decode());
        assertThat(publicKey.keySizeInBits()).isEqualTo(2048);
        assertThat(definition.secretType.isAsymmetric()).isTrue();
    }

    @Test
    void importSecretKey() {
        String env = "team5";
        Base64String importedKey = Base64String.encode(SecretKey.newKey(128).toHex().decode());
        when(vaultRunnerHelper.dtaDecryptImportedSecret(any(VaultString.class))).thenReturn(importedKey);
        when(vaultRunnerHelper.encryptSecret(any(), any())).thenReturn(VaultString.from("vault:v1:VE9fQkVfREVDUllQVEVEX0lOX1BJUEVMSU5FCg=="));
        SecretDefinition definition = createSecretDefinition(env);
        definition = definition.toBuilder().importedSecret(VaultString.from("vault:v1:ZW5jcnlwdGVkCg")).build();

        var definitions = secretDefinitionGenerator.extendWithRealSecret(Set.of(definition));

        assertThat(first(definitions).plaintextSecret).isEqualTo(importedKey);

        Set<Secret> secrets = secretGenerator.secretDefinitionsToSecrets(definitions);
        Secret secret = secrets.iterator().next();

        assertThat(secret.content).hasToString("vault:v1:VE9fQkVfREVDUllQVEVEX0lOX1BJUEVMSU5FCg==");
        assertThat(secret.secretType.isAsymmetric()).isFalse();
    }

    @Test
    void testImportCertificateAsPublicKey() {
        when(vaultRunnerHelper.dtaDecryptImportedSecret(any(VaultString.class))).thenReturn(Base64String.encode(PRIVATE_KEY));
        when(vaultRunnerHelper.encryptSecret(any(), any())).thenReturn(VaultString.from("vault:v1:VE9fQkVfREVDUllQVEVEX0lOX1BJUEVMSU5FCg=="));
        String env = "team5";
        SecretDefinition definition = createSecretDefinition(env).toBuilder()
                .importedSecret(VaultString.from("vault:v1:ZW5jcnlwdGVkCg"))
                .publicKeyOrCert(Base64String.encode(POD_CERT))
                .importedSecret(VaultString.from("vault:v1:" + getEncoder().encodeToString(PRIVATE_KEY.getBytes())))
                .secretType(SecretType.CERT_ANY_IMPORT)
                .build();
        var definitions = secretDefinitionGenerator.extendWithRealSecret(Set.of(definition));
        var secrets = secretGenerator.secretDefinitionsToSecrets(definitions);
        assertThat(first(secrets).publicKeyOrCertContent.decode()).isEqualTo(POD_CERT);
    }

    @Test
    void noPrivateKeyWhileImportingCertificate() {
        String env = "team5";
        when(vaultRunnerHelper.encryptSecret(any(), any())).thenThrow(NullPointerException.class);

        SecretDefinition definition = createSecretDefinition(env).toBuilder()
                .publicKeyOrCert(Base64String.encode(POD_CERT))
                .secretType(SecretType.CERT_ANY_IMPORT)
                .build();
        var definitions = secretDefinitionGenerator.extendWithRealSecret(Set.of(definition));
        var secrets = secretGenerator.secretDefinitionsToSecrets(definitions);

        assertThat(first(secrets).publicKeyOrCertContent.decode()).isEqualTo(POD_CERT);
        assertThat(first(secrets).content).isNull();
    }

    @Test
    @DisplayName("Given a secret definition with a plaintext when Vault cannot encrypt the secret it should crash")
    void shouldNotAddSecretIfPlaintextCannotBeNull() {
        when(vaultRunnerHelper.encryptSecret(any(), any())).thenThrow(IllegalStateException.class);
        String env = "team5";

        var def = Set.of(createSecretDefinition(env).toBuilder()
                .secretType(SecretType.KEY_128)
                .plaintextSecret(Base64String.encode(PRIVATE_KEY))
                .build());

        assertThrows(IllegalStateException.class, () -> secretGenerator.secretDefinitionsToSecrets(def));
    }

    @Test
    void testTeam1NonProduction() {
        testForEnvironment("team4", "team4-ycs-stubs", false);
    }

    @Test
    void testTeam5NonProduction() { testForEnvironment("team5", "team5-ycs-stubs", false); }

    @Test
    void testAPPACCNonProduction() {
        testForEnvironment("yfb-acc", "yfb-acc-ycs-stubs", false);
    }

    @Test
    void testTeam1Production() {
        testForEnvironment("team4", "team4-ycs-stubs", false);
    }

    @Test
    void testYFBPRDProduction() {
        testForEnvironment("yfb-prd", "yfb-prd-ycs-stubs", true);
    }

    @Test
    void testYFBExtProduction() {
        testForEnvironment("yfb-ext-prd", "yfb-ext-prd-ycs-stubs", true);
    }

    @Test
    void testDoesNotExistInThisNameSpace() {
        testForEnvironment("yfb-ext-prd", "yfb-ext-prd-ycs-stubs", true);
    }

    private void testForEnvironment(String env, String expectedPath, boolean usePrdVault) {
        when(vaultRunnerHelper.encryptSecret(any(), any())).thenReturn(VaultString.from("vault:v1:xjmlcuFNUHXFJv3dQ+Ts9g=="));
        when(vaultRunnerHelper.encryptSecret(any(), any())).thenReturn(VaultString.from("vault:v1:xjmlcuFNUHXFJv3dQ+Ts9g=="));

        SecretDefinition definition = createSecretDefinition(env);
        if (env.contains("prd")) {
            definition = definition.toBuilder().rotate(true).build();
        }
        var definitions = secretDefinitionGenerator.extendWithRealSecret(Set.of(definition));
        Set<Secret> secrets = secretGenerator.secretDefinitionsToSecrets(definitions);
        Secret secret = secrets == null ? null : secrets.iterator().next();

        if (usePrdVault && (env.contains("team") || env.contains("acc"))) {
            assertThat(secret).isNull();
        } else if (!usePrdVault && (!(env.contains("team") || env.contains("acc")))) {
            assertThat(secret).isNull();
        } else {
            assertThat(secret.secretName).isEqualTo(definition.name);
            assertThat(secret.rotate).isEqualTo(definition.rotate);
            assertThat(secret.vaultPath).isEqualTo(expectedPath);
            assertThat(secret.content.getBase64String().lengthRawBytes()).isEqualTo(128 / 8);
        }
    }



    private SecretDefinition createSecretDefinition(String env) {
        return SecretDefinition.builder()
                .projectName(PROJECTNAME)
                .gitlabRepoNamespace(REPO_PROJECT_NS)
                .secretType(SecretType.KEY_128)
                .name(NAME)
                .description(DESCRIPTION)
                .environments(allEnvironments().findEnvironments(env))
                .build();
    }

}
