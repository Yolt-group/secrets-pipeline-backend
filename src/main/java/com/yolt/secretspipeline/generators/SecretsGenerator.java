package com.yolt.secretspipeline.generators;

import com.yolt.secretspipeline.secrets.Base64String;
import com.yolt.secretspipeline.secrets.Environment;
import com.yolt.secretspipeline.secrets.Secret;
import com.yolt.secretspipeline.secrets.SecretDefinition;
import com.yolt.secretspipeline.secrets.SecretType;
import com.yolt.secretspipeline.vaultrunner.VaultRunnerHelper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.bouncycastle.openpgp.PGPException;
import org.c02e.jpgpj.Ring;

import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@AllArgsConstructor
public class SecretsGenerator {

    private final VaultRunnerHelper vaultRunnerHelper;

    public Set<Secret> secretDefinitionsToSecrets(Set<SecretDefinition> secretDefinitions) {
        return secretDefinitions.stream()
                .map(this::secretDefinitionToSecret)
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());
    }

    private Set<Secret> secretDefinitionToSecret(SecretDefinition definition) {
        Base64String publicKeyMaterial = null;
        if (definition.secretType.isAsymmetric()) {
            publicKeyMaterial = definition.publicKeyOrCert;
        }
        printInfoAboutImportedPGPKeys(definition);

        var results = new HashSet<Secret>();

        for (Environment environment : definition.environments) {
            String path = environment.getName() + "-" + environment.getNamespace() + "-" + definition.projectName;
            var encryptedSecret = definition.encryptPlaintext(path, vaultRunnerHelper::encryptSecret);
            var secret = Secret.builder()
                    .environment(environment)
                    .secretName(definition.name)
                    .publicKeyOrCertContent(publicKeyMaterial)
                    .content(encryptedSecret.orElse(null))
                    .secretType(definition.secretType)
                    .rotate(definition.rotate)
                    .pgpKeyID(definition.pgpTemplate != null ? definition.pgpTemplate.pgpID : Long.valueOf(0))
                    .vaultPath(path)
                    .pgpCertificationFingerprint(definition.pgpTemplate != null ? definition.pgpTemplate.certificationPublicKeyFingerprint : "")
                    .pgpKeyFingerprint(definition.pgpTemplate != null ? definition.pgpTemplate.keyPairPublicKeyFingerprint : "")
                    .build();
            results.add(secret);
        }
        return results;
    }

    private static void printInfoAboutImportedPGPKeys(SecretDefinition definition) {
        if (definition.importedSecret != null && definition.secretType == SecretType.GPG || definition.secretType == SecretType.GPG_PAIR) {

            var ring = new Ring();
            try {
                ring.load(definition.plaintextSecret.decode());
                for (val key : ring.getKeys()) {
                    key.getMaster().unlock("Yolt".toCharArray());
                    log.info("We have a sub key in the private keyring with its master key having fingerprint {}, id {} & {}, and purpose {}",
                            key.getMaster().getFingerprint(), key.getMaster().getId(), key.getMaster().getShortId(), key.getMaster().getUsageFlags()); //NOSHERIFF
                }
            } catch (IOException | PGPException e) {
                //this can happen for older secret definitions so only log it
                log.info("Printing key information failed for definition: {} this could be due to an old definition", definition.name);
            }
        }
    }
}