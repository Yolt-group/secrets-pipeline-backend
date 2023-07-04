package com.yolt.secretspipeline.command.io.readers;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.yolt.secretspipeline.secrets.SecretType;
import com.yolt.secretspipeline.secrets.templates.CSRTemplate;
import com.yolt.secretspipeline.secrets.templates.JWKSTemplate;
import com.yolt.secretspipeline.secrets.templates.PGPTemplate;
import lombok.AllArgsConstructor;

import java.util.Set;

@AllArgsConstructor
public class JsonSecretDefinition {

    /**
     * name of the secret
     */
    @JsonProperty(required = true)
    public final String name;

    /**
     * Type of the secret, consult SecretType for more details.
     */
    @JsonProperty(required = true)
    public final SecretType secretType;

    /**
     * Description of the secret.
     */
    @JsonProperty(required = true)
    public final String description;

    /**
     * namespace (e.g. groups) where the gitlab project lives.
     */
    @JsonProperty(required = true)
    public final String gitlabRepoNamespace;

    /**
     * Targets for this secret
     */
    @JsonProperty(required = true)
    public final Set<String> environments;

    @JsonProperty(required = true)
    public final Set<String> namespaces;

    /**
     * true if you can rotate the secret to a new definition, and you
     * are aware that this will overwrite the old secret when accepting
     * the PR in the target service repo
     */
    @JsonProperty(required = true)
    public final boolean rotate;

    /**
     * public key of the RSA key. Only use this when you import a keypair.
     * Otherwise, it is filled up by the SecretDefinitionLoader class.
     */
    public final String publicKeyOrCert;

    /**
     * carries the vault-helper encrypted secret to be prepared for consumption
     * by the targeted services.
     */
    public final String importedSecret;

    /**
     * unix epoch till when the secret is valid (in seconds)
     */
    public final Long validTilUnixEpoch;

    /**
     * if is set to true, will allow skip the too short checks in LBC.
     * Is false by default and should in the secret definition always have a
     * ticket to update in length if set to true.
     */
    public final boolean skipPasswordLengthValidation;

    public final CSRTemplate csrTemplate;

    public final JWKSTemplate jwksTemplate;

    public final PGPTemplate pgpTemplate;

}
