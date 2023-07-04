package com.yolt.secretspipeline.secrets;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.ToString;
import org.springframework.lang.Nullable;

import java.util.Objects;

@EqualsAndHashCode(of = {"secretName", "vaultPath", "environment"})
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Builder(toBuilder = true)
@Getter
public class Secret {

    /**
     * content of the secret, null when CERT_ANY_IMPORT does not have a plain text
     */
    @Nullable
    public VaultString content;

    /**
     * when SecretType = RSA, publicKey is filled
     */
    @Nullable
    public Base64String publicKeyOrCertContent;

    /**
     * indicator on whether the secret can be rotated
     */
    @JsonIgnore
    public boolean rotate;

    /**
     * name of the secret
     */
    @NonNull
    public String secretName;

    @NonNull
    public SecretType secretType;

    /**
     * Path used by vault transit backend for decryption
     */
    @NonNull
    public String vaultPath;

    /**
     * only filled in case of a newly generated PGP key(pair)
     */
    @Nullable
    public Long pgpKeyID;

    /**
     * Only filed in case of a newly generated PGP key(pair)
     */
    @Nullable
    public String pgpCertificationFingerprint;

    /**
     * Only filed in case of a newly generated PGP key(pair)
     */
    @Nullable
    public String pgpKeyFingerprint;

    @NonNull
    public Environment environment;

    public boolean secretChanged(Secret s) {
        return !Objects.equals(content, s.content);
    }
}
