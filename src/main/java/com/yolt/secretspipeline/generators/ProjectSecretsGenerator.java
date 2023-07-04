package com.yolt.secretspipeline.generators;

import com.yolt.secretspipeline.command.Options;
import com.yolt.secretspipeline.secrets.Secret;
import com.yolt.secretspipeline.secrets.SecretDefinition;
import com.yolt.secretspipeline.secrets.Secrets;

import java.util.Set;
import java.util.stream.Collectors;

public class ProjectSecretsGenerator {

    private final SecretDefinitionGenerator secretDefinitionGenerator;
    private final SecretsGenerator secretGenerator;
    private final boolean useProductionVault;

    public ProjectSecretsGenerator(SecretDefinitionGenerator secretDefinitionGenerator,
                                   SecretsGenerator secretGenerator,
                                   Options options) {
        this.secretDefinitionGenerator = secretDefinitionGenerator;
        this.secretGenerator = secretGenerator;
        this.useProductionVault = options.isUsePRDVault();
    }

    public Secrets update(Set<SecretDefinition> secretDefinitions, Secrets existingSecrets) {
        var envSecretDefinitions = filterOnEnvironment(secretDefinitions);
        var extendedDefinitions = secretDefinitionGenerator.extendWithRealSecret(envSecretDefinitions);
        var secrets = secretGenerator.secretDefinitionsToSecrets(extendedDefinitions);

        existingSecrets.upsert(secrets);
        return filterOnEnvironment(existingSecrets, secrets);
    }

    private Secrets filterOnEnvironment(Secrets existingSecrets, Set<Secret> updatedSecrets) {
        var environments = updatedSecrets.stream()
                .map(secret -> secret.environment)
                .collect(Collectors.toSet());

        return new Secrets(
                existingSecrets.getYoltSecrets().stream()
                        .filter(s -> environments.contains(s.environment))
                        .collect(Collectors.toList())
        );
    }

    private Set<SecretDefinition> filterOnEnvironment(Set<SecretDefinition> secretDefinitions) {
        return secretDefinitions.stream()
                .filter(def -> useProductionVault ? def.environments.isProductionEnvironment() : def.environments.isDTAEnvironment())
                .collect(Collectors.toSet());
    }
}
