package com.yolt.secretspipeline.secrets.templates;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.ToString;

@Builder(toBuilder = true)
@EqualsAndHashCode
@ToString
@JsonIgnoreProperties(ignoreUnknown = true)
public class JWKSTemplate {

    @JsonCreator
    public JWKSTemplate(@JsonProperty("alg") String alg, @JsonProperty("use") String use, @JsonProperty("kty") String kty, @JsonProperty("keySize") Integer keySize, @JsonProperty("kid") String kid) {
        this.alg = alg;
        this.use = use;
        this.kty = kty;
        this.keySize = keySize == null ? 2048 : keySize;
        this.kid = kid;
    }

    /**
     * algorithm used
     */
    @NonNull
    public final String alg;

    /**
     * use, currently only supporting KeyUse com.nimbusds.jose.jwk.
     */
    @NonNull
    public final String use;

    @NonNull
    public final String kty;

    /**
     * Keysize, defaulting to 2048
     */
    @NonNull
    public final Integer keySize;

    /**
     * key id used in the jwks, will be filled in by the pipeline
     */
    public final String kid;

}
