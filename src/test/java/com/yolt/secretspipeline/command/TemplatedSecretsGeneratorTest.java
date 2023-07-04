package com.yolt.secretspipeline.command;

import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.yolt.secretspipeline.generators.SecretsGeneratorTest;
import com.yolt.secretspipeline.secrets.SecretDefinition;
import com.yolt.secretspipeline.secrets.SecretType;
import com.yolt.secretspipeline.secrets.UnixEpoch;
import com.yolt.secretspipeline.secrets.templates.CSRTemplate;
import com.yolt.secretspipeline.secrets.templates.JWKSTemplate;
import com.yolt.secretspipeline.secrets.templates.PGPTemplate;
import com.yolt.secretspipeline.secrets.templates.TemplatedSecretGenerator;
import com.yolt.securityutils.crypto.PrivateKey;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.c02e.jpgpj.CompressionAlgorithm;
import org.c02e.jpgpj.Decryptor;
import org.c02e.jpgpj.EncryptionAlgorithm;
import org.c02e.jpgpj.Encryptor;
import org.c02e.jpgpj.Key;
import org.c02e.jpgpj.Ring;
import org.c02e.jpgpj.Subkey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

import static com.yolt.secretspipeline.secrets.Environments.AllEnvironments.allEnvironments;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TemplatedSecretsGeneratorTest {

    private long secretKeyID1;
    private long secretKeyID2;
    private long attestationKeyID1;
    private long attestationKeyID2;

    @BeforeEach
    void init() {
        secretKeyID1 = secretKeyID2 = attestationKeyID2 = attestationKeyID1 = 0;
    }

    @Test
    void generateCSRKeyPair() {
        SecretDefinition definition = createBaseDefinition(SecretType.CSR);
        CSRTemplate csrTemplate = new CSRTemplate(
                "CN=Duke, OU=JavaSoft, O=Sun Microsystems, C=US",
                4096,
                "SHA256withRSA",
                new HashSet<>(Arrays.asList("nonRepudiation", "digitalSignature")),
                Collections.emptySet(),
                Collections.emptyList());
        definition = definition.toBuilder().csrTemplate(csrTemplate).build();

        TemplatedSecretGenerator templatedSecretGenerator = new TemplatedSecretGenerator();
        definition = templatedSecretGenerator.generateCSRKeyPair(definition);

        PrivateKey rsaPrivateKey = PrivateKey.from(definition.plaintextSecret.decode());
        PKCS10CertificationRequest csr = convertPemToPKCS10CertificationRequest(definition.publicKeyOrCert.decode());

        assertThat(rsaPrivateKey.isPrivateKey()).isTrue();
        assertThat(new DefaultAlgorithmNameFinder().getAlgorithmName(csr.getSignatureAlgorithm())).isEqualTo("SHA256WITHRSA");
    }

    @Test
    void testGeneratePGPPairSigning() throws IOException, PGPException {
        SecretDefinition definition = createBaseDefinition(SecretType.GPG_PAIR);
        PGPTemplate signerTemplate = new PGPTemplate("yolt@yolt.io", 2048, PGPPublicKey.RSA_SIGN, 0L, null, null, null, null);
        definition = definition.toBuilder().pgpTemplate(signerTemplate).build();
        Ring[] keyrings = getFilledRingsForEqualsTesting(definition);
        assertThat(keyrings[0].getEncryptionKeys().size()).isZero();
        assertThat(keyrings[1].getEncryptionKeys().size()).isZero();
        assertThat(keyrings[0].getSigningKeys().size()).isEqualTo(1);
        assertThat(keyrings[1].getSigningKeys().size()).isEqualTo(1);
        //investigate if we have the signing key and not the attestation key:
        assertThat(keyrings[0].getSigningKeys().contains(keyrings[0].findAll(secretKeyID1).get(0))).isTrue();
        assertThat(keyrings[0].getSigningKeys().contains(keyrings[0].findAll(attestationKeyID1).get(0))).isTrue();
        assertThat(keyrings[1].getSigningKeys().contains(keyrings[1].findAll(secretKeyID2).get(0))).isTrue();
        assertThat(keyrings[1].getSigningKeys().contains(keyrings[1].findAll(attestationKeyID2).get(0))).isTrue();
        assertThat(keyrings[0].getVerificationKeys().size()).isEqualTo(2); // you get the keyring verification keypair with the signing keypair free :(...
        assertThat(keyrings[1].getVerificationKeys().size()).isEqualTo(2);// you get the keyring verification keypair with the signing keypair free :(...
        assertThat(keyrings[0].getVerificationKeys().contains(keyrings[0].findAll(secretKeyID1).get(0))).isTrue();
        assertThat(keyrings[0].getVerificationKeys().contains(keyrings[0].findAll(attestationKeyID1).get(0))).isTrue();
        assertThat(keyrings[1].getVerificationKeys().contains(keyrings[1].findAll(secretKeyID2).get(0))).isTrue();
        assertThat(keyrings[1].getVerificationKeys().contains(keyrings[1].findAll(attestationKeyID2).get(0))).isTrue();
        assertThat(keyrings[1].getVerificationKeys().get(0).getMaster().getPublicKey().getValidSeconds() > 0).isTrue();
    }

    @Test
    void testGeneratePGPPairEncryption() throws IOException, PGPException {
        SecretDefinition definition = createBaseDefinition(SecretType.GPG_PAIR);
        PGPTemplate signerTemplate = new PGPTemplate("yolt@yolt.io", 2048, PGPPublicKey.RSA_ENCRYPT, 0L, null, null, null, null);
        definition = definition.toBuilder().pgpTemplate(signerTemplate).build();
        Ring[] keyrings = getFilledRingsForEqualsTesting(definition);
        assertThat(keyrings[0].getEncryptionKeys().size()).isEqualTo(2); //2 pairs, crypto and verification...
        assertThat(keyrings[0].getEncryptionKeys().get(0)).isEqualTo(keyrings[0].findAll(secretKeyID1).get(0));
        assertThat(keyrings[0].getSigningKeys().size()).isEqualTo(1); //thje certification keypair is in as well...
        assertThat(keyrings[0].getSigningKeys().get(0)).isEqualTo(keyrings[0].findAll(attestationKeyID1).get(0));
        assertThat(keyrings[0].getVerificationKeys().size()).isEqualTo(2); // you get the keypair verification key for free :(...
        assertThat(keyrings[1].getEncryptionKeys().size()).isEqualTo(2); //2 pairs, crypto and verification...
        assertThat(keyrings[1].getSigningKeys().size()).isEqualTo(1); //2 times the certification keypair
        assertThat(keyrings[1].getVerificationKeys().size()).isEqualTo(2); // you get the keyring verification key for free :(...
        testGPGEncryption(keyrings[0]);
    }

    @Test
    void testGPGEncryptDecrypt() throws IOException, PGPException {
        SecretDefinition pgptemplate = createBaseDefinition(SecretType.GPG_PAIR);
        PGPTemplate encryptionTemplate = new PGPTemplate("test", 2048, PGPPublicKey.RSA_ENCRYPT, 0L, null, null, null, null);
        pgptemplate = pgptemplate.toBuilder().pgpTemplate(encryptionTemplate).build();
        TemplatedSecretGenerator templatedSecretGenerator = new TemplatedSecretGenerator();
        SecretDefinition definition = templatedSecretGenerator.generatePGPKeypairSecretDefinition(pgptemplate);
        secretKeyID1 = templatedSecretGenerator.getSecondaryKeyPairID();
        Ring ring = new Ring();
        loadSubkeyToRing(ring, definition.plaintextSecret.decode());
        loadSubkeyToRing(ring, definition.publicKeyOrCert.decode());
        PGPTemplate signerTemplate = new PGPTemplate("test", 2048, PGPPublicKey.RSA_SIGN, 0L, null, null, null, null);
        pgptemplate = pgptemplate.toBuilder().pgpTemplate(signerTemplate).build();
        definition = templatedSecretGenerator.generatePGPKeypairSecretDefinition(pgptemplate);
        secretKeyID2 = templatedSecretGenerator.getSecondaryKeyPairID();
        ring.load(definition.plaintextSecret.decode());
        ring.load(definition.publicKeyOrCert.decode());
        testGPGEncryption(ring);
    }

    @Test
    void testMultiPurposeKeyPairGenerationAndUsage() throws IOException, PGPException {
        PGPTemplate pgpTemplate = new PGPTemplate("yolt@yolt.com", 2048, PGPPublicKey.RSA_ENCRYPT, 0L, null, null, null, PGPPublicKey.RSA_SIGN);

        SecretDefinition secretDefinitionWithPGPtemplate = createBaseDefinition(SecretType.GPG_PAIR)
                .toBuilder()
                .pgpTemplate(pgpTemplate)
                .validTilUnixEpoch(new UnixEpoch(1893456000L))
                .build();

        TemplatedSecretGenerator templatedSecretGenerator = new TemplatedSecretGenerator();
        SecretDefinition definition = templatedSecretGenerator.generatePGPKeypairSecretDefinition(secretDefinitionWithPGPtemplate);
        secretKeyID1 = templatedSecretGenerator.getSecondaryKeyPairID();
        long secretSecondaryKeyId1 = templatedSecretGenerator.getSecondaryKeyPairID();
        Ring ring = new Ring();
        loadSubkeyToRing(ring, definition.plaintextSecret.decode());
        List<Subkey> encryptionKeys = ring.findAll(secretKeyID1).get(0).getSubkeys()
                .stream()
                .filter(subkey -> (subkey.getSecretKey().getKeyID() == secretKeyID1))
                .collect(Collectors.toList());
        assertThat(encryptionKeys.size()).isEqualTo(1);
        assertThat(encryptionKeys.get(0).isForEncryption()).isTrue();
        assertThat(encryptionKeys.get(0).isForDecryption()).isTrue();
        List<Subkey> verifcationKeys = ring.findAll(secretSecondaryKeyId1).get(0).getSubkeys()
                .stream()
                .filter(subkey -> (subkey.getSecretKey().getKeyID() == secretSecondaryKeyId1))
                .collect(Collectors.toList());
        assertThat(verifcationKeys.get(0).isForEncryption()).isTrue();
        assertThat(verifcationKeys.get(0).isForDecryption()).isTrue();
        assertThat(ring.findAll(secretSecondaryKeyId1).get(0).getMaster().isForVerification()).isTrue();
    }

    @Test
    void testGPGFlagsAndDueDate() throws IOException, PGPException {
        SecretDefinition pgptemplate = createBaseDefinition(SecretType.GPG_PAIR);
        //valid till 2030-01-01
        PGPTemplate encryptionTemplate = PGPTemplate.builder().identity("yoltEncrypt@yolt.io").strength(2048).purpose(PGPPublicKey.RSA_ENCRYPT).build();
        pgptemplate = pgptemplate.toBuilder().pgpTemplate(encryptionTemplate).validTilUnixEpoch(new UnixEpoch(1893456000L)).build();
        pgptemplate = pgptemplate.toBuilder().pgpTemplate(encryptionTemplate).build();
        TemplatedSecretGenerator templatedSecretGenerator = new TemplatedSecretGenerator();
        SecretDefinition definition = templatedSecretGenerator.generatePGPKeypairSecretDefinition(pgptemplate);
        secretKeyID1 = templatedSecretGenerator.getSecondaryKeyPairID();
        Ring ring = new Ring();
        loadSubkeyToRing(ring, definition.plaintextSecret.decode());
        assertThat(ring.findAll(secretKeyID1).get(0).getSubkeys().get(1).isForDecryption()).isTrue();
        assertThat(ring.findAll(secretKeyID1).get(0).getSubkeys().get(1).isForEncryption()).isTrue();
        assertThat(ring.findAll(secretKeyID1).get(0).getMaster().isForVerification()).isTrue();
        assertThat(ring.getEncryptionKeys().size() > 0).isTrue();
        assertThat(ring.getDecryptionKeys().size() > 0).isTrue();
        assertThat(ring.findAll(secretKeyID1).get(0).getMaster()).isNotEqualTo(ring.findAll(secretKeyID1).get(0).getSubkeys().get(1));
        assertThat(ring.findAll(secretKeyID1).get(0).getMaster()).isEqualTo(ring.findAll(secretKeyID1).get(0).getSubkeys().get(0));
        assertThat(ring.findAll(secretKeyID1).get(0).getMaster().getPublicKey().getValidSeconds()).isGreaterThanOrEqualTo(1893456000L - LocalDateTime.now().toEpochSecond(ZoneOffset.UTC));
    }

    private void testGPGEncryption(Ring keyring) throws IOException, PGPException {
        Encryptor encryptor = new Encryptor(keyring);
        Decryptor decryptor = new Decryptor(keyring);
        ByteArrayOutputStream cipherTextBuffer = new ByteArrayOutputStream();
        encryptor.setCompressionAlgorithm(CompressionAlgorithm.Uncompressed);
        encryptor.setEncryptionAlgorithm(EncryptionAlgorithm.AES256);
        encryptor.encrypt(IOUtils.toInputStream("test", StandardCharsets.UTF_8), cipherTextBuffer);
        assertThat(cipherTextBuffer.toString()).isNotEqualTo("test");
        ByteArrayOutputStream clearTextBuffer = new ByteArrayOutputStream();
        InputStream cipherTextStream = new ByteArrayInputStream(cipherTextBuffer.toByteArray());
        decryptor.decrypt(cipherTextStream, clearTextBuffer);
        assertThat(clearTextBuffer.toString()).hasToString("test");
    }

    @Test
    void testJWKSSigningGeneration() throws ParseException {
        SecretDefinition definition = createBaseDefinition(SecretType.JWKS);
        JWKSTemplate jwksTemplate = JWKSTemplate.builder().alg("PS512").kty("RSA").use("sig").kid("Test").build();
        definition = definition.toBuilder().jwksTemplate(jwksTemplate).build();
        TemplatedSecretGenerator templatedSecretGenerator = new TemplatedSecretGenerator();
        definition = templatedSecretGenerator.generateJWKSKeyPair(definition);
        RSAKey rsaPrivateKey = RSAKey.parse(definition.plaintextSecret.decode());
        RSAKey rsaPublicKey = RSAKey.parse(definition.publicKeyOrCert.decode());
        assertThat(rsaPublicKey.isPrivate()).isFalse();
        assertThat(rsaPrivateKey.isPrivate()).isTrue();
        assertThat(rsaPublicKey.getAlgorithm().getName()).isEqualTo("PS512");
        assertThat(rsaPublicKey.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
    }

    @Test
    void noKeySizeShouldDefaultTo2048() {
        JWKSTemplate jwksTemplate = JWKSTemplate.builder().alg("PS512").kty("RSA").use("sig").kid("Test").build();
        assertThat(jwksTemplate.keySize).isEqualTo(2048);
    }

    @Test
    void keySizeTooSmallShouldFail() {
        SecretDefinition definition = createBaseDefinition(SecretType.JWKS).toBuilder().jwksTemplate(
                        JWKSTemplate.builder().alg("PS512").kty("RSA").use("sig").kid("Test").keySize(1024).build())
                .build();

        var templatedSecretGenerator = new TemplatedSecretGenerator();

        assertThatThrownBy(() -> templatedSecretGenerator.generateJWKSKeyPair(definition))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testJWKSEncryptionGenerationDifferentKeySizes() throws ParseException {
        SecretDefinition definition = createBaseDefinition(SecretType.JWKS).toBuilder().jwksTemplate(
                JWKSTemplate.builder().alg("PS512").kty("RSA").use("sig").kid("Test").keySize(4096).build()
        ).build();

        TemplatedSecretGenerator templatedSecretGenerator = new TemplatedSecretGenerator();
        definition = templatedSecretGenerator.generateJWKSKeyPair(definition);
        RSAKey rsaPrivateKey = RSAKey.parse(definition.plaintextSecret.decode());
        RSAKey rsaPublicKey = RSAKey.parse(definition.publicKeyOrCert.decode());

        assertThat(rsaPublicKey.isPrivate()).isFalse();
        assertThat(rsaPrivateKey.isPrivate()).isTrue();
        assertThat(rsaPublicKey.getAlgorithm().getName()).isEqualTo("PS512");
        assertThat(rsaPublicKey.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        assertThat(rsaPublicKey.size()).isEqualTo(4096);
    }

    private Ring[] getFilledRingsForEqualsTesting(SecretDefinition definition) throws IOException, PGPException {
        Ring[] keyRings = new Ring[2];
        TemplatedSecretGenerator templatedSecretGenerator1 = new TemplatedSecretGenerator();
        TemplatedSecretGenerator templatedSecretGenerator2 = new TemplatedSecretGenerator();
        SecretDefinition pgpArmor1 = templatedSecretGenerator1.generatePGPKeypairSecretDefinition(definition);
        SecretDefinition pgpArmor2 = templatedSecretGenerator2.generatePGPKeypairSecretDefinition(definition);
        secretKeyID1 = templatedSecretGenerator1.getSecondaryKeyPairID();
        attestationKeyID1 = templatedSecretGenerator1.getCertificationKeyPairID();
        secretKeyID2 = templatedSecretGenerator2.getSecondaryKeyPairID();
        attestationKeyID2 = templatedSecretGenerator2.getCertificationKeyPairID();
        assertThat(pgpArmor1).isNotEqualTo(pgpArmor2);

        keyRings[0] = new Ring();
        keyRings[1] = new Ring();
        loadSubkeyToRing(keyRings[0], pgpArmor1.plaintextSecret.decode()); //private part
        loadSubkeyToRing(keyRings[0], pgpArmor1.publicKeyOrCert.decode()); //public part
        testNoSecretKey(pgpArmor1.publicKeyOrCert.decode());
        loadSubkeyToRing(keyRings[1], pgpArmor2.plaintextSecret.decode()); //private part
        loadSubkeyToRing(keyRings[1], pgpArmor2.publicKeyOrCert.decode()); //public part
        testNoSecretKey(pgpArmor2.publicKeyOrCert.decode());
        return keyRings;
    }

    private void loadSubkeyToRing(Ring ring, String code) throws IOException, PGPException {
        Key secretKey = new Key(code);
        for (Subkey subkey : secretKey.getSubkeys()) {
            subkey.setPassphrase("yolt");
        }
        ring.getKeys().add(secretKey);
    }

    private void testNoSecretKey(String armoredKey) throws IOException, PGPException {
        Key key = new Key(armoredKey);
        assertThat(key.getSubkeys().size() > 0).isTrue();
        for (Subkey subkey : key.getSubkeys()) {
            assertThat(subkey.getSecretKey()).isNull();
        }
    }

    private SecretDefinition createBaseDefinition(SecretType secretType) {
        return SecretDefinition.builder()
                .projectName(SecretsGeneratorTest.PROJECTNAME)
                .gitlabRepoNamespace(SecretsGeneratorTest.REPO_PROJECT_NS)
                .secretType(secretType)
                .name(SecretsGeneratorTest.NAME)
                .validTilUnixEpoch(new UnixEpoch().plus(1, ChronoUnit.DAYS))
                .description(SecretsGeneratorTest.DESCRIPTION)
                .environments(allEnvironments().findEnvironments("team4"))
                .build();
    }

    public PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(String pem) {
        try {
            Object o = new PEMParser(new StringReader(pem)).readObject();
            if (o instanceof PKCS10CertificationRequest) {
                return (PKCS10CertificationRequest) o;
            }
            return null;
        } catch (IOException e) {
            return null;
        }
    }
}