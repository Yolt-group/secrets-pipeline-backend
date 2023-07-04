package com.yolt.secretspipeline.secrets;

import com.yolt.secretspipeline.secrets.templates.CSRTemplate;
import com.yolt.secretspipeline.secrets.templates.JWKSTemplate;
import com.yolt.secretspipeline.secrets.templates.PGPTemplate;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.glassfish.jersey.internal.guava.Preconditions;
import org.springframework.lang.Nullable;

import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Function;

import static org.apache.commons.lang3.StringUtils.overlay;
import static org.apache.commons.lang3.StringUtils.repeat;

@Builder(toBuilder = true)
@EqualsAndHashCode
@RequiredArgsConstructor
public class SecretDefinition {

    private static final int MAX_LENGTH_SECRET_NAME = 22;

    @NonNull
    public final String name;
    @NonNull
    public final SecretType secretType;
    @NonNull
    public final String description;
    @NonNull
    public final String gitlabRepoNamespace;
    @NonNull
    public final Environments environments;

    public final boolean rotate;
    @Nullable
    public final Base64String publicKeyOrCert;
    @Nullable
    public final VaultString importedSecret;
    @Nullable
    public final UnixEpoch validTilUnixEpoch;
    @NonNull
    public final String projectName;
    @Nullable
    public final boolean skipPasswordLengthValidation;
    @Nullable
    public final Base64String plaintextSecret;
    @Nullable
    public final PGPTemplate pgpTemplate;
    @Nullable
    public final JWKSTemplate jwksTemplate;
    @Nullable
    public final CSRTemplate csrTemplate;

    public void validate() {
        Preconditions.checkArgument(name.length() <= MAX_LENGTH_SECRET_NAME, "The name '" + name + "' of the secret exceeds the maximum length of " + MAX_LENGTH_SECRET_NAME + " characters");
        Preconditions.checkArgument(name.equals(name.toLowerCase()), "The name of they key should not contain capitals! " + name + " has capitals, please rename it");
        Preconditions.checkArgument(!name.endsWith("_s"), "The name of the secret should not end with '_s', please rename " + name);
        //todo move this to a specific SecretDefinition type only applicable for passwords
        if (skipPasswordLengthValidation && !secretType.isPassword()) {
            throw new IllegalStateException("Skip password length validation can only be used in combination with passwords, please check secret `" + name + "`");
        }
        //todo move this to a specific SecretDefinition type only applicable for passwords
        if (skipPasswordLengthValidation && importedSecret == null) {
            throw new IllegalStateException("Skip password can only be used for imported passwords, please check secret `" + name + "`");
        }
        if (!secretType.validateKey(plaintextSecret, skipPasswordLengthValidation)) {
            throw new IllegalArgumentException("The key length of the secret `" + name + "` for env: '" + environments + "' does not match the required length. Please consult https://git.yolt.io/security/secrets-pipeline-docker/-/blob/master/src/main/java/com/yolt/secretspipeline/secrets/SecretDefinition.java for the actual checks. Password: '" + maskSecret(plaintextSecret) + "'");
        }
        if (!hasPublicOrCert() && secretType.isAsymmetric()) {
            //todo move this to a specific SecretDefinition type only applicable for RSA* or PGP
            throw new IllegalStateException("When you import a secret of type RSA_* or PGP_Pair, then add the public key, error at secret with name " + name);
        }
        if (this.pgpTemplate != null) {
            //todo move this to a specific SecretDefinition type only applicable for PGP
            Preconditions.checkArgument(validTilUnixEpoch != null, "Please supply validTilUnixEpoch when creating a PGP secret " + name);
        }
    }

    public static String maskSecret(Base64String secret) {
        return overlay(secret.decode(), repeat("*", secret.lengthRawBytes() - 2), 1, secret.lengthRawBytes() - 1);
    }

    public boolean hasPublicOrCert() {
        return this.publicKeyOrCert != null && (this.publicKeyOrCert.getBase64() != null);
    }

    private boolean shouldGenerateSecret() {
        return this.secretType.supportGeneration() && this.importedSecret == null;
    }

    public SecretDefinition extendWithRealSecret(Function<VaultString, Base64String> decryptor) {
        if (shouldGenerateSecret()) {
            return secretType.generateKey(this);
        } else if (importedSecret != null) {
            return toBuilder().plaintextSecret(decryptor.apply(importedSecret)).build();
        }
        return this;
    }

    public Optional<VaultString> encryptPlaintext(String vaultPath, BiFunction<Base64String, String, VaultString> encryptor) {
        return secretType.encryptPlaintext(name, plaintextSecret, vaultPath, encryptor);
    }

    public static class SecretDefinitionBuilder {

        public SecretDefinitionBuilder pgpTemplate(PGPTemplate pgpTemplate) {
            if (pgpTemplate != null) {
                Preconditions.checkArgument(pgpTemplate.identity != null, "Please supply an identity in the secret template of " + name + "!");
                Preconditions.checkArgument(pgpTemplate.strength != 0, "Please supply a strength in the secret template of " + name + "!");
                Preconditions.checkArgument(pgpTemplate.purpose != 0, "Please supply a purpose in the secret template of " + name + "!");
                this.pgpTemplate = pgpTemplate;
            }
            return this;
        }
    }
}
