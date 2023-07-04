package com.yolt.secretspipeline.secrets;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.beans.ConstructorProperties;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
public class Secrets {

    @Getter
    private final List<Secret> yoltSecrets = new ArrayList<>();

    @ConstructorProperties("yoltSecrets")
    public Secrets(Collection<Secret> yoltSecrets) {
        this.yoltSecrets.addAll(yoltSecrets);
    }

    public void upsert(Set<Secret> secrets) {
        secrets.forEach(this::upsert);
    }

    public boolean contains(Secret secret) {
        return this.yoltSecrets.stream().anyMatch(s -> s.equals(secret));
    }

    public Optional<Secret> find(Secret secret) {
        return this.yoltSecrets.stream().filter(s -> s.equals(secret)).findFirst();
    }

    public void upsert(Secret newSecret) {
        int index = findSecret(newSecret);

        if (index == -1) {
            log.info("Adding new secret: {}/{}", newSecret.getSecretName(), newSecret.getVaultPath()); //NOSHERIFF path and encrypted secrets are not sensitive
            yoltSecrets.add(newSecret);
        } else {
            var existing = yoltSecrets.get(index);
            if (newSecret.rotate && existing.secretChanged(newSecret)) {
                log.info("Replacing secret: {}/{}", newSecret.getSecretName(), newSecret.getVaultPath()); //NOSHERIFF secret names and paths are not sensitive
                yoltSecrets.set(index, newSecret);
            }
        }
    }

    private int findSecret(Secret secret) {
        for (var i = 0; i < yoltSecrets.size(); i++) {
            if (yoltSecrets.get(i).equals(secret)) {
                return i;
            }
        }
        return -1;
    }

    public int size() {
        return yoltSecrets.size();
    }

    public Map<Environment, List<Secret>> groupByEnvironment() {
        return yoltSecrets.stream().collect(
                Collectors.toMap(
                        s -> s.environment,
                        s -> {
                            var result = new ArrayList<Secret>();
                            result.add(s);
                            return result;
                        },
                        (s1, s2) -> {
                            s1.addAll(s2);
                            return s1;
                        }));
    }
}
