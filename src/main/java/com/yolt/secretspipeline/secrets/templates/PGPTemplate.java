package com.yolt.secretspipeline.secrets.templates;


import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import org.springframework.lang.Nullable;

@Builder(toBuilder = true)
@EqualsAndHashCode
@ToString
@RequiredArgsConstructor
public class PGPTemplate {

    /**
     * "hello@hello.nl" for PGP
     * can be DN/OU/CN values for CSR
     */
    public final String identity;

    /**
     * Strenght of RSA key, can be 2048 or 4096
     */
    public final Integer strength;

    /**
     * Purpose of PGP keys, can be:
     * PGPPublicKey.RSA_SIGN;
     * PGPPublicKey.RSA_ENCRYPT;
     *
     * @see <a href="https://www.bouncycastle.org/docs/pgdocs1.5on/org/bouncycastle/openpgp/PGPPublicKey.html">org.bouncycastle.openpgp.PGPPublicKey</a>
     */
    public final Integer purpose;

    //Filled in by the generator:
    /**
     * only contains public key id when generated
     */
    @Nullable
    public final Long pgpID;

    /**
     * only contains the fingerprint of the attestation key when generated
     */
    @Nullable
    public final String certificationPublicKeyFingerprint;

    /**
     * only contains the fingerprint of the to be Secret key when generated
     */
    @Nullable
    public final String keyPairPublicKeyFingerprint;

    /**
     * only contains the fingerprint of the secondary Secret key when generated
     */
    @Nullable
    public final String secondaryKeyPairPublickKeyFingerprint;

    //added, optional new field:
    /**
     * Secondary purpose of PGP keys, can be:
     * PGPPublicKey.RSA_SIGN;
     * PGPPublicKey.RSA_ENCRYPT;
     *
     * @see <a href="https://www.bouncycastle.org/docs/pgdocs1.5on/org/bouncycastle/openpgp/PGPPublicKey.html">org.bouncycastle.openpgp.PGPPublicKey</a>
     * If not 0, This will geenrate a second subkey with the secondary purpose
     */
    @Nullable
    public final Integer secondaryPurpose;

}

