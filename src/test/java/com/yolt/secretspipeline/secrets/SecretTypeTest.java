package com.yolt.secretspipeline.secrets;

import org.apache.commons.lang3.StringUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import static com.yolt.secretspipeline.secrets.SecretType.PASSWORD_ALFA_NUMERIC;
import static com.yolt.secretspipeline.secrets.SecretType.PASSWORD_ALFA_NUMERIC_SPECIAL_CHARS;
import static org.assertj.core.api.Assertions.assertThat;

class SecretTypeTest {

    @Test
    void shouldReturnCorrectLength() {
        var definition = SecretDefinition.builder()
                .name("test")
                .secretType(SecretType.KEY_128)
                .description("test")
                .gitlabRepoNamespace("backend")
                .environments(Environments.AllEnvironments.allEnvironments())
                .projectName("test")
                .build();

        assertThat(SecretType.KEY_128.validateKey(SecretType.KEY_128.generateKey(definition).plaintextSecret, false)).isTrue();
        assertThat(SecretType.KEY_160.validateKey(SecretType.KEY_160.generateKey(definition).plaintextSecret, false)).isTrue();
        assertThat(SecretType.KEY_192.validateKey(SecretType.KEY_192.generateKey(definition).plaintextSecret, false)).isTrue();
        assertThat(SecretType.KEY_224.validateKey(SecretType.KEY_224.generateKey(definition).plaintextSecret, false)).isTrue();
        assertThat(SecretType.KEY_256.validateKey(SecretType.KEY_256.generateKey(definition).plaintextSecret, false)).isTrue();
        assertThat(SecretType.KEY_512.validateKey(SecretType.KEY_512.generateKey(definition).plaintextSecret, false)).isTrue();
        assertThat(SecretType.RSA_2048.validateKey(SecretType.RSA_2048.generateKey(definition).plaintextSecret, false)).isTrue();
        assertThat(SecretType.RSA_4096.validateKey(SecretType.RSA_4096.generateKey(definition).plaintextSecret, false)).isTrue();
        assertThat(PASSWORD_ALFA_NUMERIC_SPECIAL_CHARS.validateKey(PASSWORD_ALFA_NUMERIC_SPECIAL_CHARS.generateKey(definition).plaintextSecret, false)).isTrue();
        assertThat(PASSWORD_ALFA_NUMERIC.validateKey(PASSWORD_ALFA_NUMERIC.generateKey(definition).plaintextSecret, false)).isTrue();
    }

    @Test
    void shouldFailWhenKeyLengthIsWrong() {
        var definition = SecretDefinition.builder()
                .name("test")
                .secretType(SecretType.KEY_128)
                .description("test")
                .gitlabRepoNamespace("backend")
                .environments(Environments.AllEnvironments.allEnvironments())
                .projectName("test")
                .build();

        assertThat(SecretType.KEY_160.validateKey(SecretType.KEY_128.generateKey(definition).plaintextSecret, false)).isFalse();
        assertThat(SecretType.RSA_2048.validateKey(SecretType.generateRSAKey(1024).getSecretKey(), false)).isFalse();
    }

    @Test
    void testPasswordDistribution() {
        String[] password1 = new String[1000];
        String[] password2 = new String[1000];
        for (int i = 0; i < 1000; i++) {
            password1[i] = SecretType.generatePassword(false).decode();
            password2[i] = SecretType.generatePassword(true).decode();
        }
        passwordContentTesting(password1, false);
        passwordContentTesting(password2, true);
    }

    @Test
    void ecPrivateKeyCertLengthTooShort() {
        var key = """
                -----BEGIN EC PRIVATE KEY-----
                MEQCAQEEEC6ebg5dQhVQrJFj5kCqGWKgBwYFK4EEAByhJAMiAAQfkdgfy3EQKafu
                jS6spB/fKDhGGPyfNzQCTkKKPnWo1w==
                -----END EC PRIVATE KEY-----
                """;

        Assertions.assertThat(SecretType.CERT_ANY_IMPORT.validateKey(Base64String.encode(key), false)).isFalse();
    }

    @Test
    void ecPrivateKeyCertLengthCorrect() {
        var key = """
                -----BEGIN EC PRIVATE KEY-----
                MHcCAQEEIFdC6BW5VW7NOu+d9QpPn5VYc9Wzk0/8JsPvYVzLKUwkoAoGCCqGSM49
                AwEHoUQDQgAEExaUn7t24Wnt3WsEDB3dgHRd0PSgkAWtUpdv4sgO9Cx9nq5cjqLY
                R3iaT+qPXydPEYsHdM/9khG8d4wmgZkn5w==
                -----END EC PRIVATE KEY-----
                """;

        Assertions.assertThat(SecretType.CERT_ANY_IMPORT.validateKey(Base64String.encode(key), false)).isTrue();
    }

    @Test
    void rsaPrivateKeyTooShort() {
        var key = """
                -----BEGIN RSA PRIVATE KEY-----
                MIICXQIBAAKBgQCtcgcSFUKFjcZtVkJlYF1K5/ZzP/voJ+DMUtKcHG1bSYAfy+/7
                MQYDHduL8Wd+SuwhuCGrF1xk+s9TDJedxf13RcWNuljDYpd1JrFefun+u6OCi9dA
                A3FHDYVhxzl/2pZ9FMvyki0UP58kArN81TlMkB94m5vKYnKqSMfmPA1JSwIDAQAB
                AoGAZKJZeeN98lF9ROkcowdTeee2tc31EhE5PDP94PgZdzLhNRG1zu/1xg8n2D2b
                x8oe0b2tQ0DNqgVgD5apzbAXzIxUw0SkWXcUKClY32PJ9tok5+6jr94ktr4f0jRV
                ZfnArRV3r0rMapW/rffJ29RBJnrxcZoONV16BG8MaDfdDnECQQDgz13pLZL0AihC
                X1ivnVt2EpK6uZ4ksx2GAvr5/oW7BnOKtVvsvqfBQBKhcjNQQC9FWj/qMgYNm0La
                V03SchVjAkEAxYJU1fwmKzwUr7Fh4m/udyAFLo62ljzQKhRzy1B2/rzc3m73aieH
                Zug49p1h50ljAybIrrix5LlWcfEWoUZU+QJAVOm+fP67zPKrpjZBV0PGchid122Y
                8B+/fQjPJ3IdrQDIz5GlAQ0abAH5h4WNIDi+IiHullUCuEz2uWXUfTKeJQJBAMKj
                2wj6MX8/+T7fdxBYsE+TLaghGkzaZ2Zgu3Bsvqfx5VQLVSW3CNfgGGro1FfC2aF8
                ch7FgwJdp5QoO935WrkCQQCHgu1PiyhOmHt6YfF4LbEtRJOe0C/gcSD1gHUEjroU
                kOtx/XYmdaMivRMrxT7ilt72Wr/6ortS3iPzfJ9d2ciX
                -----END RSA PRIVATE KEY-----
                """;

        Assertions.assertThat(SecretType.CERT_ANY_IMPORT.validateKey(Base64String.encode(key), false)).isFalse();
    }

    @Test
    void rsaPrivateKeyLengthCorrect() {
        var key = """
                -----BEGIN RSA PRIVATE KEY-----
                MIIEowIBAAKCAQEAz+Tq9I0iLLFa9eWpcjRey4H39B29xW32snJZj2N2SA4q62Zq
                s+3tTbm0eNJcCf1Pw1yGIiAy6/I4uuzurtgqylXksmKPyphDp+0dnLlo2OKnps6b
                Cbwf3OHJ7HxlGmEaXyg6MuevzOmeox8wHM1flHDxQdNaKaEte7QaWLbDf2r3Mf4b
                UGd64qpRUnZVgZ5VeGnNPuOBW5kI51wrSTd3bp40BXV1YUFVhn9TrlZHZu1/rKZs
                2I+MeFWyqYxIZV64OATGl7JKpsDK6uDy1vJHiAyciBILnf7St/AjXo/e8Uck/ITS
                So1X++Fdz1zqnQKrYjkHZpsHH9lgX0+86ZhZZwIDAQABAoIBAG1EtrGe1I2FEngY
                I/2gxQpV34txbmMsrvOP4r7Y2jx5JdngVMkJjybBKrguaK3fdGMMaHvbTKhzAZpO
                Gg3QFH2Qs8mGwGkNqtHCcUQEt7T3PIMSKK7vMBganNUtdL5utzu4mw5SdDZRvE2k
                gNdCorAUxNmCSuuCibNxMD/cn9iB37OEtTVntY+poRqzITjxvVFTQn31+jv89j2g
                5kjsdS6R4Jb3NrPp46GHtLoqaz/If+BCPWbAgC0b45UwXjTy2KA/cWdX6sczOVIq
                6XR7g47dblxRqiqexFoincGD8kxhwuMMonvrBpvOzdHpUZBRXJwXrTiVSTpkrNsw
                jxgaGLECgYEA6C40qWqsXNMIJy0CJoaG+6nEV90YNhmWFfi7mauJHPaDaTiaUMs4
                uzLSODQKF4Impn1Oazm9zvaSVMmY9+oFrAy+dLRJMqugxcTE7IcQ8FLJUNlkvCZB
                gGvUjWm11EzZGV58mB+a+LSCpGqN7tOn9geu1Y9qRIw5GPP9dIGz8IUCgYEA5Tjg
                pFgs+27Xp2bHWOlDJxGpwWqXC83qfwjLQie3UMUyD3M2sRm5Dg+iaxblAbIA9CRu
                z1u9T3kF0Vve5Vz5ImHiSe4pgVeq2DSCxC/yDBz0ALYBMsdE310D/2ZLeA144vVr
                lKPO7tAP8tZUgmVuxIihZvoWRisttsuGShDPm/sCgYEAwt81OBTegjJln2v5aBh1
                ZvjAYPajAZVMETjpTDtbI8IL3d6yNqm6/fPT2XRkHAMTKZ32maynEPSHMT7bcwkq
                pZM0r4M6BJtkn1ld5yAeKXdynLc6A2kghQb8KYzWHlA5zz8s2Al+6sum8xSz+AYR
                7T/ZkEmE6e+/ZKA01Pqf6nkCgYBIO4AuycqDAQ7cJbsz/W235g0Ecj5e7eizV2YV
                1sYhocKAs+HMNTrnf23DKVfJDPrX9JMmrNYfMRfwPW8kAARSHV5dxbs2kxW3Q/Th
                Neqkfos1niUKh1jgukMEPIwTrMsnWgcos+YFw3MDJx9CaAxbymJyPOS//+NL8x7C
                QEHr+QKBgFB2NpSjy8UZ8pWKrj4bmSvsiq+iWlheoNMigjoyARZKOmrsfkBm1nMP
                PjhzguhWJHqIb+RLalB8hZLP7olD2bD5plQxBDBEiiMcGdeRlPw20IGIg283bwml
                g+GWYcGdbGfCM9vsn79mLoJW8roEAnD0rdX/UX7Y9TsGTJnos6ny
                -----END RSA PRIVATE KEY-----
                """;

        Assertions.assertThat(SecretType.CERT_ANY_IMPORT.validateKey(Base64String.encode(key), false)).isTrue();
    }

    private void passwordContentTesting(String[] pw, boolean special) {
        int hasSpecialChars = 0;
        for (String password : pw) {
            assertThat(password).containsPattern(".*[A-Z].*");
            assertThat(password).containsPattern(".*[a-z].*");
            if (!special) {
                assertThat(StringUtils.isAlphanumeric(password)).isTrue();
            } else {
                if (!StringUtils.isAlphanumeric(password)) {
                    hasSpecialChars++;
                }
            }
        }
        if (special) {
            assertThat(hasSpecialChars).isBetween(100, 1001); //not all will have special chars.
        }
    }
}
