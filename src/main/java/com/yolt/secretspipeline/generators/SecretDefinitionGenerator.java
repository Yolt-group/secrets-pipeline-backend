package com.yolt.secretspipeline.generators;

import com.yolt.secretspipeline.secrets.Base64String;
import com.yolt.secretspipeline.secrets.SecretDefinition;
import com.yolt.secretspipeline.secrets.VaultString;
import com.yolt.secretspipeline.vaultrunner.VaultRunnerHelper;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * This class will:
 * <p>
 * - for imported secrets we only have the ciphertext we need to decrypt it with Vault DTA and PRD to get the plaintext
 * - for generated secrets we only have the definition we need to generate the keys (RSA, PGP, etc.)
 */
public class SecretDefinitionGenerator {

    private final VaultRunnerHelper vaultRunnerHelper;

    public SecretDefinitionGenerator(VaultRunnerHelper vaultRunnerHelper) {
        this.vaultRunnerHelper = vaultRunnerHelper;
    }

    /**
     * Extend the secret, by importing or generating a new one.
     *
     * @return set of definitions for each environment a separate one
     */
    public Set<SecretDefinition> extendWithRealSecret(Set<SecretDefinition> secretDefinitions) {
        var result = new HashSet<SecretDefinition>();
        var errorCatcher = new ErrorCollector<SecretDefinition>();

        for (SecretDefinition definition : secretDefinitions) {
            errorCatcher.trySafe((SecretDefinition def) -> {
                var extendedDefinition = definition.extendWithRealSecret(decryptor(definition.environments.isProductionEnvironment()));
                extendedDefinition.validate();
                result.add(extendedDefinition);
            }, definition);
        }
        if (errorCatcher.hasErrors()) {
            var errors = errorCatcher.getErrors().stream().distinct()
                    .map(error -> String.format("Error occurred during processing secret: %s (%s) on environments [%s] exception is: %s",
                            error.getOriginalObject().name,
                            error.getOriginalObject().secretType,
                            error.getOriginalObject().environments,
                            error.getOriginalException().getMessage()))
                    .collect(Collectors.toList());
            throw new IllegalStateException(String.join("\n", errors));
        }

        return result;
    }

    private Function<VaultString, Base64String> decryptor(boolean usingPrdVault) {
        if (usingPrdVault) {
            return vaultRunnerHelper::prdDecryptImportedSecret;
        }
        return vaultRunnerHelper::dtaDecryptImportedSecret;
    }


}
