package com.yolt.secretspipeline.secrets.templates;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.yolt.secretspipeline.secrets.Base64String;
import com.yolt.secretspipeline.secrets.SecretDefinition;
import com.yolt.securityutils.crypto.CryptoUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Hex;

import javax.security.auth.x500.X500Principal;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest;
import static org.bouncycastle.bcpg.PublicKeyAlgorithmTags.RSA_ENCRYPT;
import static org.bouncycastle.bcpg.PublicKeyAlgorithmTags.RSA_SIGN;
import static org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags.AES_256;

/**
 * Currently supports PGP, JWKS and CSR
 */
@Slf4j
public class TemplatedSecretGenerator {

    private long generatedKeyPairID;
    private long certificationKeyPairID;
    private String secretKeyFingerprint;
    private String certificationKeyPairFingerprint;
    private String secondaryKeyPairFingerprint;

    public SecretDefinition generateJWKSKeyPair(SecretDefinition definition) {
        if (definition.jwksTemplate.kty.contains("RSA")) {
            Set<KeyOperation> keyOperationSet = new HashSet<>();

            var keyUse = new KeyUse(definition.jwksTemplate.use);
            if (KeyUse.SIGNATURE.getValue().equals(definition.jwksTemplate.use)) {
                keyOperationSet.add(KeyOperation.SIGN);
                keyOperationSet.add(KeyOperation.VERIFY);
            } else if (KeyUse.ENCRYPTION.getValue().equals(definition.jwksTemplate.use)) {
                keyOperationSet.add(KeyOperation.DECRYPT);
                keyOperationSet.add(KeyOperation.ENCRYPT);
            } else {
                throw new IllegalStateException("We currently only support sign and encrypt");
            }
            try {
                RSAKey jwk = new RSAKeyGenerator(definition.jwksTemplate.keySize)
                        .keyUse(keyUse) // indicate the intended use of the key
                        .keyOperations(keyOperationSet)
                        .keyID(UUID.randomUUID().toString()) // give the key a unique ID
                        .algorithm(new Algorithm(definition.jwksTemplate.alg))
                        .generate();
                return definition.toBuilder()
                        .plaintextSecret(Base64String.encode(jwk.toString()))
                        .publicKeyOrCert(Base64String.encode(jwk.toPublicJWK().toString()))
                        .build();
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }
        } else {
            throw new IllegalStateException("We currently only support RSA generation");
        }
    }

    public SecretDefinition generatePGPKeypairSecretDefinition(SecretDefinition definition) {
        String identity = definition.pgpTemplate.identity;

        int strength = definition.pgpTemplate.strength;
        int purpose = definition.pgpTemplate.purpose;
        Integer secondaryPurpose = definition.pgpTemplate.secondaryPurpose;
        log.info("Generated GPG key will be valid till {}", definition.validTilUnixEpoch.toDate());
        try {
            //First make the keyring generator which set our identity and holds the key we want to create.
            var keyRingGenerator = generateKeyRingGenerator(identity, strength, purpose, secondaryPurpose, definition.validTilUnixEpoch.duration());

            //Now have public key ring with 1 attestation key and our desired public key
            PGPPublicKeyRing pkr = keyRingGenerator.generatePublicKeyRing();
            log.info("The validity time of the key in seconds is {}", pkr.getPublicKey().getValidSeconds());

            var bos = new ByteArrayOutputStream();
            var pubOut = new ArmoredOutputStream(bos);
            pkr.encode(pubOut, true);
            pubOut.close();
            var attestationAndTargetedPublicKey = Base64String.encode(bos.toByteArray());

            //now create a secret key ring with our targeted key inside
            var skr = keyRingGenerator.generateSecretKeyRing();
            var secretBuffer = new ByteArrayOutputStream();
            var privout = new ArmoredOutputStream(new BufferedOutputStream(secretBuffer));
            skr.encode(privout);
            privout.close();
            log.info("You can share the following public key with external parties if required; \n{}", bos);

            var targettedPGPKeyPair = Base64String.encode(secretBuffer.toByteArray());

            return definition.toBuilder().pgpTemplate(
                    definition.pgpTemplate.toBuilder()
                            .pgpID(generatedKeyPairID)
                            .certificationPublicKeyFingerprint(certificationKeyPairFingerprint)
                            .keyPairPublicKeyFingerprint(secretKeyFingerprint)
                            .secondaryKeyPairPublickKeyFingerprint(secondaryKeyPairFingerprint)
                            .build())
                    .plaintextSecret(targettedPGPKeyPair).publicKeyOrCert(attestationAndTargetedPublicKey)
                    .build();
        } catch (IOException | PGPException e) {
            throw new RuntimeException("Cannot create secret", e);
        }
    }

    public long getCertificationKeyPairID() {
        return certificationKeyPairID;
    }

    public long getSecondaryKeyPairID(){
        return generatedKeyPairID;
    }

    private PGPKeyRingGenerator generateKeyRingGenerator(String identity, int strength, int purpose, Integer secondaryPurpose, long validityPeriod) throws PGPException {
        var creationDate = new Date();
        // set up the certification material to show that the key comes from us (identity):
        var kpg = new RSAKeyPairGenerator(); //todo: instead of generating this, we need to import it from a secret from the pipeline to have it stabilized. https://yolt.atlassian.net/browse/STY-417
        kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), CryptoUtils.getSecureRandom(), 4096, 12));

        PGPKeyPair certificationKeyPair = new BcPGPKeyPair(RSA_SIGN, kpg.generateKeyPair(), creationDate);

        // set up the values for certification of the keyring
        var signhashgen = new PGPSignatureSubpacketGenerator();
        signhashgen.setKeyFlags(true, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);
        signhashgen.setPreferredSymmetricAlgorithms(true, new int[]{AES_256});
        signhashgen.setPreferredHashAlgorithms(true, new int[]{HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256});
        signhashgen.setSignatureExpirationTime(true, validityPeriod);
        signhashgen.setKeyExpirationTime(true, validityPeriod);
        PGPDigestCalculator sha1Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
        PGPDigestCalculator sha256Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);
        // set up keyring encryption (maybe can ditch this later)
        var pske = new BcPBESecretKeyEncryptorBuilder(AES_256, sha256Calc, 0xc0).build("yolt".toCharArray());
        var keyRingGen =
                new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, certificationKeyPair,
                        identity, sha1Calc, signhashgen.generate(), null,
                        new BcPGPContentSignerBuilder(certificationKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256), pske);
        // now create the keypair that we want to provide:

        var keyPair = generatePGPKeyPair(strength, purpose, creationDate);
        var keyPairHashGenerator = getPgpSignatureSubpacketGenerator(purpose, validityPeriod);
        generatedKeyPairID = keyPair.getKeyID();
        certificationKeyPairID = certificationKeyPair.getKeyID();
        log.info("Created secret keypair with purpose {}, and KeyID {}. Please note that the signing key with keyID {} is not yet stable, see https://yolt.atlassian.net/browse/STY-417 .", purpose, generatedKeyPairID, certificationKeyPair.getKeyID());
        secretKeyFingerprint = getFingerprint(keyPair);
        certificationKeyPairFingerprint = getFingerprint(certificationKeyPair);
        log.info("The secret key its public key has fingerprint {}, the attestation keypair has fingerprint {}", secretKeyFingerprint, certificationKeyPairFingerprint);
        if (secondaryPurpose != null) {
            var secondaryKeyPair = generatePGPKeyPair(strength, secondaryPurpose, creationDate);
            var secondaryKeyPairHashGenerator = getPgpSignatureSubpacketGenerator(secondaryPurpose, validityPeriod);
            long secondaryKeyPairID = secondaryKeyPair.getKeyID();
            secondaryKeyPairFingerprint = getFingerprint(secondaryKeyPair);
            log.info("A secondary secret keypair with purpose {} has fingerprint {}, and keyID {} has been added to the same attestation key", secondaryPurpose, secondaryKeyPairFingerprint, secondaryKeyPairID);
            keyRingGen.addSubKey(secondaryKeyPair, secondaryKeyPairHashGenerator.generate(), null);
        }
        keyRingGen.addSubKey(keyPair, keyPairHashGenerator.generate(), null);
        return keyRingGen;
    }

    private PGPKeyPair generatePGPKeyPair(int strength, int purpose, Date creationDate) throws PGPException {
        var rsaKeyPairGenerator = new RSAKeyPairGenerator();
        rsaKeyPairGenerator.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), CryptoUtils.getSecureRandom(), strength, 12));
        if (purpose != RSA_SIGN && purpose != RSA_ENCRYPT && purpose != PublicKeyAlgorithmTags.RSA_GENERAL) {
            throw new IllegalArgumentException("Wrong purpose defined");
        }
        return new BcPGPKeyPair(purpose, rsaKeyPairGenerator.generateKeyPair(), creationDate);
    }

    private PGPSignatureSubpacketGenerator getPgpSignatureSubpacketGenerator(int purpose, long validityPeriod) {
        var keyPairHashGenerator = new PGPSignatureSubpacketGenerator();
        if (purpose == RSA_ENCRYPT) {
            keyPairHashGenerator.setKeyFlags(true, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
        } else if (purpose == RSA_SIGN) {
            keyPairHashGenerator.setKeyFlags(true, KeyFlags.SIGN_DATA | KeyFlags.AUTHENTICATION);
        }
        keyPairHashGenerator.setSignatureExpirationTime(true, validityPeriod);
        keyPairHashGenerator.setPreferredHashAlgorithms(true, new int[]{HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256});
        keyPairHashGenerator.setPreferredSymmetricAlgorithms(true, new int[]{AES_256});
        keyPairHashGenerator.setPreferredCompressionAlgorithms(true, new int[]{CompressionAlgorithmTags.UNCOMPRESSED});
        keyPairHashGenerator.setKeyExpirationTime(true, validityPeriod);
        return keyPairHashGenerator;
    }

    private String getFingerprint(PGPKeyPair keyPair) {
        return new String(Hex.encode(keyPair.getPublicKey().getFingerprint()));
    }

    public SecretDefinition generateCSRKeyPair(SecretDefinition definition) {
        var provider = new BouncyCastleProvider();
        KeyPair keyPair;
        try {
            var kpg = KeyPairGenerator.getInstance("RSA", provider);
            kpg.initialize(definition.csrTemplate.strength, CryptoUtils.getSecureRandom());
            keyPair = kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Could not generate RSA KeyPair", e);
        }

        var csrSubject = new X500Principal(definition.csrTemplate.subject);
        var csrExtensions = getExtensions(definition.csrTemplate, keyPair.getPublic());
        var pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(csrSubject, keyPair.getPublic());

        pkcs10Builder.addAttribute(pkcs_9_at_extensionRequest, csrExtensions);

        ContentSigner signGen;
        try {
            signGen = new JcaContentSignerBuilder(definition.csrTemplate.signatureAlgorithm)
                    .setProvider(provider)
                    .build(keyPair.getPrivate());
        } catch (OperatorCreationException e) {
            throw new IllegalStateException("Could not sign PKCS10CertificationRequest", e);
        }
        var csr = pkcs10Builder.build(signGen);

        var csrPem = new StringWriter();
        try (var pem = new JcaPEMWriter(csrPem)) {
            pem.writeObject(csr);
        } catch (IOException e) {
            throw new IllegalStateException("Could not write to PEM for PKCS10CertificationRequest", e);
        }

        var keyPem = new StringWriter();
        try (var pem = new JcaPEMWriter(keyPem)) {
            pem.writeObject(keyPair.getPrivate());
        } catch (IOException e) {
            throw new IllegalStateException("Could not write to PEM for PrivateKey", e);
        }

        return definition.toBuilder()
                .plaintextSecret(Base64String.encode(keyPem.toString()))
                .publicKeyOrCert(Base64String.encode(csrPem.toString()))
                .build();
    }

    private Extensions getExtensions(CSRTemplate definition, PublicKey publicKey) {
        try {
            var extensionsGenerator = new ExtensionsGenerator();
            var extensionUtils = new JcaX509ExtensionUtils();
            extensionsGenerator.addExtension(Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(publicKey));

            if (definition.keyUsage != null && !definition.keyUsage.isEmpty()) {
                extensionsGenerator.addExtension(Extension.keyUsage, true, getKeyUsage(definition));
            }
            if (definition.subjectAlternativeNames != null && !definition.subjectAlternativeNames.isEmpty()) {
                extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, getSubjectAlternativeNames(definition));
            }
            if (definition.extendedKeyUsage != null && !definition.extendedKeyUsage.isEmpty()) {
                extensionsGenerator.addExtension(Extension.extendedKeyUsage, false, getExtendedKeyUsage(definition));
            }

            return extensionsGenerator.generate();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Could not get the Subject Key Identifier for the Public Key", e);
        } catch (IOException e) {
            throw new IllegalStateException("Could not add extensions", e);
        }
    }

    private KeyUsage getKeyUsage(CSRTemplate definition) {
        return new KeyUsage(definition.keyUsage.stream()
                .map(this::getKeyUsage)
                .reduce(null, (i, j) -> i == null ? j : i | j));
    }

    private int getKeyUsage(String keyUsage) {
        return switch (keyUsage) {
            case "digitalSignature" -> KeyUsage.digitalSignature;
            case "nonRepudiation" -> KeyUsage.nonRepudiation;
            case "keyEncipherment" -> KeyUsage.keyEncipherment;
            case "dataEncipherment" -> KeyUsage.dataEncipherment;
            case "keyAgreement" -> KeyUsage.keyAgreement;
            case "keyCertSign" -> KeyUsage.keyCertSign;
            case "cRLSign" -> KeyUsage.cRLSign;
            case "encipherOnly" -> KeyUsage.encipherOnly;
            case "decipherOnly" -> KeyUsage.decipherOnly;
            default -> throw new IllegalStateException("Illegal keyUsage " + keyUsage);
        };
    }

    private ExtendedKeyUsage getExtendedKeyUsage(CSRTemplate definition) {
        return new ExtendedKeyUsage(definition.extendedKeyUsage.stream()
                .map(this::getExtendedKeyUsage)
                .toArray(KeyPurposeId[]::new));
    }

    private KeyPurposeId getExtendedKeyUsage(String extendedKeyUsage) {
        return switch (extendedKeyUsage) {
            case "serverAuth" -> KeyPurposeId.id_kp_serverAuth;
            case "clientAuth" -> KeyPurposeId.id_kp_clientAuth;
            case "codeSigning" -> KeyPurposeId.id_kp_codeSigning;
            case "emailProtection" -> KeyPurposeId.id_kp_emailProtection;
            case "ipsecEndSystem" -> KeyPurposeId.id_kp_ipsecEndSystem;
            case "ipsecTunnel" -> KeyPurposeId.id_kp_ipsecTunnel;
            case "ipsecUser" -> KeyPurposeId.id_kp_ipsecUser;
            case "timeStamping" -> KeyPurposeId.id_kp_timeStamping;
            case "OCSPSigning" -> KeyPurposeId.id_kp_OCSPSigning;
            case "dvcs" -> KeyPurposeId.id_kp_dvcs;
            case "sbgpCertAAServerAuth" -> KeyPurposeId.id_kp_sbgpCertAAServerAuth;
            case "scvp_responder" -> KeyPurposeId.id_kp_scvp_responder;
            case "eapOverPPP" -> KeyPurposeId.id_kp_eapOverPPP;
            case "eapOverLAN" -> KeyPurposeId.id_kp_eapOverLAN;
            case "scvpServer" -> KeyPurposeId.id_kp_scvpServer;
            case "scvpClient" -> KeyPurposeId.id_kp_scvpClient;
            case "ipsecIKE" -> KeyPurposeId.id_kp_ipsecIKE;
            case "capwapAC" -> KeyPurposeId.id_kp_capwapAC;
            case "capwapWTP" -> KeyPurposeId.id_kp_capwapWTP;
            case "smartcardlogon" -> KeyPurposeId.id_kp_smartcardlogon;
            case "macAddress" -> KeyPurposeId.id_kp_macAddress;
            case "msSGC" -> KeyPurposeId.id_kp_msSGC;
            case "nsSGC" -> KeyPurposeId.id_kp_nsSGC;
            default -> throw new IllegalStateException("Illegal extendedKeyUsage " + extendedKeyUsage);
        };
    }

    private GeneralNames getSubjectAlternativeNames(CSRTemplate definition) {
        return new GeneralNames(definition.subjectAlternativeNames.stream()
                .map(domain -> new GeneralName(GeneralName.dNSName, domain))
                .toArray(GeneralName[]::new));
    }
}
