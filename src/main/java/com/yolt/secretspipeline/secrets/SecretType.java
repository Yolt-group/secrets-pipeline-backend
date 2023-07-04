package com.yolt.secretspipeline.secrets;

import com.nimbusds.jose.jwk.RSAKey;
import com.yolt.secretspipeline.secrets.templates.TemplatedSecretGenerator;
import com.yolt.securityutils.crypto.CryptoUtils;
import com.yolt.securityutils.crypto.PrivateKey;
import com.yolt.securityutils.crypto.RSA;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.RandomStringGenerator;
import org.apache.commons.text.TextRandomProvider;

import java.security.interfaces.ECKey;
import java.text.ParseException;
import java.util.Optional;
import java.util.function.BiFunction;

@AllArgsConstructor
@Slf4j
public enum SecretType {
    /**
     * Key used in case of AES-128
     */
    KEY_128("KEY_128") {
        public SecretDefinition generateKey(SecretDefinition definition) {
            return definition.toBuilder().plaintextSecret(generateBitKey(128).getSecretKey()).build();
        }

        @Override
        public boolean validateKey(Base64String key, boolean skipPasswordLengthValidation) {
            return key.lengthRawBytes() * 8 == 128;
        }
    },
    /**
     * Key used in case of SHA-1 HMACs
     */
    KEY_160("KEY_160") {
        public SecretDefinition generateKey(SecretDefinition definition) {
            return definition.toBuilder().plaintextSecret(generateBitKey(160).getSecretKey()).build();
        }

        @Override
        public boolean validateKey(Base64String key, boolean skipPasswordLengthValidation) {
            return key.lengthRawBytes() * 8 == 160;
        }
    },
    /**
     * Key used in case of AES-192
     */
    KEY_192("KEY_192") {
        public SecretDefinition generateKey(SecretDefinition definition) {
            return definition.toBuilder().plaintextSecret(generateBitKey(192).getSecretKey()).build();
        }

        @Override
        public boolean validateKey(Base64String key, boolean skipPasswordLengthValidation) {
            return key.lengthRawBytes() * 8 == 192;
        }
    },
    /**
     * key used in case of SHA-224 HMAC
     */
    KEY_224("KEY_224") {
        public SecretDefinition generateKey(SecretDefinition definition) {
            return definition.toBuilder().plaintextSecret(generateBitKey(224).getSecretKey()).build();
        }

        @Override
        public boolean validateKey(Base64String key, boolean skipPasswordLengthValidation) {
            return key.lengthRawBytes() * 8 == 224;
        }
    },
    /**
     * Key used in case of SHA-256, SHA3-256 HMAC and AES-256
     */
    KEY_256("KEY_256") {
        @Override
        public SecretDefinition generateKey(SecretDefinition definition) {
            return definition.toBuilder().plaintextSecret(generateBitKey(256).getSecretKey()).build();

        }

        @Override
        public boolean validateKey(Base64String key, boolean skipPasswordLengthValidation) {
            return key.lengthRawBytes() * 8 == 256;
        }
    },
    /**
     * Key used in case of HMACS with the following algorithms: SHA-512, SHA-384, SHA3-512, SHA3-384
     */
    KEY_512("KEY_512") {
        @Override
        public SecretDefinition generateKey(SecretDefinition definition) {
            return definition.toBuilder().plaintextSecret(generateBitKey(512).getSecretKey()).build();
        }

        @Override
        public boolean validateKey(Base64String key, boolean skipPasswordLengthValidation) {
            return key.lengthRawBytes() * 8 == 512;
        }
    },
    /**
     * Key used in case of RSA signing or encryption
     * keypair returned consists of privatekey-pem RSA_KEY_SEPARATOR publickey-pem
     */
    RSA_2048("RSA_2048") {
        @Override
        public SecretDefinition generateKey(SecretDefinition definition) {
            var keyPair = SecretType.generateRSAKey(2048);
            return definition.toBuilder().plaintextSecret(keyPair.getSecretKey()).publicKeyOrCert(keyPair.getPublicKey()).build();
        }

        @Override
        public boolean isAsymmetric() {
            return true;
        }

        @Override
        public boolean validateKey(Base64String key, boolean skipPasswordLengthValidation) {
            return PrivateKey.from(key.decode()).ensureKeySize(2048);
        }

    },
    /**
     * Key used in case of RSA signing or encryption
     */
    RSA_4096("RSA_4096") {
        @Override
        public SecretDefinition generateKey(SecretDefinition definition) {
            var keyPair = SecretType.generateRSAKey(4096);
            return definition.toBuilder().plaintextSecret(keyPair.getSecretKey()).publicKeyOrCert(keyPair.getPublicKey()).build();
        }

        @Override
        public boolean isAsymmetric() {
            return true;
        }

        @Override
        public boolean validateKey(Base64String key, boolean skipPasswordLengthValidation) {
            return PrivateKey.from(key.decode()).ensureKeySize(4096);
        }

    },
    /**
     * GPG keys (only import of symmetric keys)
     */
    GPG("GPG") {
        @Override
        public SecretDefinition generateKey(SecretDefinition definition) {
            throw new UnsupportedOperationException("Generating GPG keys is not yet supported, only importing is. Or do you want to create GPG_Pair with the TemplatedSecretGenerator");
        }

        @Override
        public boolean isAsymmetric() {
            return false;
        }

    },
    /**
     * GPG keys (only import of keypairs)
     */
    GPG_PAIR("GPG_PAIR") {
        @Override
        public SecretDefinition generateKey(SecretDefinition definition) {
            TemplatedSecretGenerator generator = new TemplatedSecretGenerator();
            return generator.generatePGPKeypairSecretDefinition(definition);
        }

        @Override
        public boolean isAsymmetric() {
            return true;
        }
    },

    /**
     * Alfanumeric password of 64 chars(PASSWORD_LENGTH) long with uppercase, lowercase and 0-9.
     */
    PASSWORD_ALFA_NUMERIC("PASSWORD_ALFA_NUMERIC") {
        @Override
        public SecretDefinition generateKey(SecretDefinition definition) {
            return definition.toBuilder().plaintextSecret(generatePassword(false)).build();
        }

        @Override
        public boolean validateKey(Base64String key, boolean skipPasswordLengthValidation) {
            return PASSWORD_ALFA_NUMERIC_SPECIAL_CHARS.validateKey(key, skipPasswordLengthValidation);
        }
    },
    /**
     * extension of the Alfanumeric password, now with special printable ASCII characters mixed into it.
     */
    PASSWORD_ALFA_NUMERIC_SPECIAL_CHARS("PASSWORD_ALFA_NUMERIC_SPECIAL_CHARS") {
        @Override
        public SecretDefinition generateKey(SecretDefinition definition) {
            return definition.toBuilder().plaintextSecret(generatePassword(true)).build();
        }

        @Override
        public boolean validateKey(Base64String key, boolean skipPasswordLengthValidation) {
            if (skipPasswordLengthValidation) {
                return true;
            } else {
                return key.lengthRawBytes() >= 12; //imported password need to be >= 12 characters
            }
        }
    },

    CERT_ANY_IMPORT("CERT_ANY_IMPORT") {
        @Override
        public SecretDefinition generateKey(SecretDefinition definition) {
            throw new UnsupportedOperationException("Generating certificates is not supported, only importing is.");
        }

        @Override
        public boolean supportGeneration() {
            return false;
        }

        @Override
        Optional<VaultString> encryptPlaintext(String name, Base64String plaintext, String vaultPath, BiFunction<Base64String, String, VaultString> encryptor) {
            if (plaintext == null) {
                return Optional.empty();
            }
            return Optional.of(encryptor.apply(plaintext, vaultPath));
        }

        @Override
        public boolean validateKey(Base64String key, boolean skipPasswordLengthValidation) {
            if (key == null) {
                return true; //imported private key is optional for certificate imports
            }
            var privateKey = PrivateKey.from(key.decode());
            if (privateKey.getKey() instanceof ECKey) {
                return privateKey.keySizeInBits() >= 224;
            } else if (privateKey.getKey() instanceof java.security.interfaces.RSAKey) {
                return privateKey.keySizeInBits() >= 2048;
            }
            return false;
        }

        @Override
        public boolean isAsymmetric() {
            return true;
        }

    },
    CSR("CSR") {
        @Override
        public SecretDefinition generateKey(SecretDefinition definition) {
            TemplatedSecretGenerator generator = new TemplatedSecretGenerator();
            return generator.generateCSRKeyPair(definition);
        }

        @Override
        public boolean isAsymmetric() {
            return true;
        }
    },
    JWKS("JWKS") {
        @Override
        public SecretDefinition generateKey(SecretDefinition definition) {
            TemplatedSecretGenerator generator = new TemplatedSecretGenerator();
            return generator.generateJWKSKeyPair(definition);
        }

        @Override
        public boolean isAsymmetric() {
            return true;
        }

        @Override
        public boolean validateKey(Base64String key, boolean skipPasswordLengthValidation) {
            try {
                var rsaPrivateKey = RSAKey.parse(key.decode());
                return rsaPrivateKey.size() >= 2048 && rsaPrivateKey.size() % 1024 == 0;
            } catch (ParseException e) {
                throw new IllegalArgumentException("Cannot parse the JWKS key as we currently only support RSA");
            }
        }
    };

    public boolean isPassword() {
        return this == PASSWORD_ALFA_NUMERIC || this == PASSWORD_ALFA_NUMERIC_SPECIAL_CHARS;
    }

    public static final int PASSWORD_LENGTH = 64;

    public abstract SecretDefinition generateKey(SecretDefinition definition);

    public boolean isAsymmetric() {
        return false;
    }

    public boolean validateKey(Base64String key, boolean skipPasswordLengthValidation) {
        return true;
    }

    public boolean supportGeneration() {
        return true;
    }

    Optional<VaultString> encryptPlaintext(String name, Base64String plaintext, String vaultPath, BiFunction<Base64String, String, VaultString> encryptor) {
        if (plaintext == null) {
            throw new IllegalStateException("Plaintext is empty for: " + name);
        }
        return Optional.of(encryptor.apply(plaintext, vaultPath));
    }

    @Getter
    private final String value;

    private static SecretsKeyPair generateBitKey(int length) {
        byte[] key = CryptoUtils.getRandomKey(length);
        return SecretsKeyPair.of(Base64String.encode(key));
    }

    static SecretsKeyPair generateRSAKey(int length) {
        var keyPair = RSA.Builder.generateKeys(length);
        var publicKeyPem = Base64String.encode(keyPair.getPublicKey().toPem());
        var privateKeyPem = Base64String.encode(keyPair.getPrivateKey().toPem().trim());

        return SecretsKeyPair.of(privateKeyPem, publicKeyPem);
    }

    public static Base64String generatePassword(boolean useSpecialChars) {
        char[][] pairs;
        if (useSpecialChars) {
            pairs = new char[][]{{'a', 'z'}, {'0', '9'}, {'A', 'Z'}, {' ', '*'}};
        } else {
            pairs = new char[][]{{'a', 'z'}, {'0', '9'}, {'A', 'Z'}};
        }

        var randomStringGenerator = new RandomStringGenerator.Builder()
                .usingRandom(new TextRandomWrapper())
                .withinRange(pairs)
                .build();

        return Base64String.encode(randomStringGenerator.generate(PASSWORD_LENGTH));
    }

    public static class TextRandomWrapper implements TextRandomProvider {

        @Override
        public int nextInt(int max) {
            return CryptoUtils.getSecureRandom().nextInt(max);
        }
    }

}
