package com.yolt.secretspipeline.secrets;

import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.toList;

public class SecretDefinitions implements Iterable<SecretDefinition> {

    private final List<SecretDefinition> definitions;

    public SecretDefinitions(List<SecretDefinition> definitions) {
        this.definitions = definitions;
        validate(definitions);
    }

    public boolean isEmpty() {
        return definitions == null || definitions.isEmpty();
    }

    private void validate(List<SecretDefinition> secretDefinitions) {
        validateNoMixOfEnvironments(secretDefinitions);
        validatePrivateKeyAndPublicKeyDifferent(secretDefinitions);
    }

    private void validatePrivateKeyAndPublicKeyDifferent(List<SecretDefinition> secretDefinitions) {
        for (SecretDefinition secretDefinition : secretDefinitions) {
            if (secretDefinition.plaintextSecret != null && secretDefinition.plaintextSecret.equals(secretDefinition.publicKeyOrCert)) {
                throw new IllegalStateException("Private key part of '" + secretDefinition.name + "' is the same as the public part");
            }
        }
    }

    private void validateNoMixOfEnvironments(List<SecretDefinition> secretDefinitions) {
        for (SecretDefinition secretDefinition : secretDefinitions) {
            if (secretDefinition.environments.isDTAEnvironment() && secretDefinition.environments.isProductionEnvironment()) {
                throw new IllegalStateException("Secret definition '" + secretDefinition.name + "' contains a PRD env as well as a DTA env this is not possible, please create a separate definition for DTA and PRD");
            }
        }
    }

    public Map<Project, Set<SecretDefinition>> groupSecretDefinitionsByProject() {
        return definitions.stream().collect(
                Collectors.toMap(
                        s -> new Project(s.projectName),
                        s -> {
                            var result = new HashSet<SecretDefinition>();
                            result.add(s);
                            return result;
                        },
                        (s1, s2) -> {
                            s1.addAll(s2);
                            return s1;
                        }));
    }

    @Override
    public Iterator<SecretDefinition> iterator() {
        return definitions.iterator();
    }

    public SecretDefinitions filterDTAEnvironments() {
        return new SecretDefinitions(definitions.stream()
                .filter(def -> def.environments.isDTAEnvironment())
                .collect(toList()));
    }
}
