package com.yolt.secretspipeline.secrets;

import lombok.Getter;

@Getter
public class SecretsKeyPair {

    private final Base64String secretKey;
    private final Base64String publicKey;

    private SecretsKeyPair(Base64String secretKey, Base64String publicKey) {
        this.secretKey = secretKey;
        this.publicKey = publicKey;
    }

    public static SecretsKeyPair of(Base64String secretKey, Base64String publicKey) {
        return new SecretsKeyPair(secretKey, publicKey);
    }

    public static SecretsKeyPair of(Base64String secretKey) {
        return new SecretsKeyPair(secretKey, null);
    }
}
