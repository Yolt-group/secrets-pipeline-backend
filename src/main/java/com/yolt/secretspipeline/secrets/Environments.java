package com.yolt.secretspipeline.secrets;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.experimental.UtilityClass;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@EqualsAndHashCode
public class Environments implements Iterable<Environment> {

    @UtilityClass
    public static class AllEnvironments {

        private Environments environments;

        public static Environments allEnvironments() {
            if (environments != null) {
                return environments;
            }
            environments = new Environments(readEnvironments());
            return environments;
        }

        private static List<Environment> readEnvironments() {
            try (InputStream is = AllEnvironments.class.getResourceAsStream("/environments.txt")) {
                return IOUtils.readLines(is, StandardCharsets.UTF_8).stream()
                        .flatMap(AllEnvironments::parse)
                        .collect(Collectors.toList());
            } catch (IOException e) {
                throw new IllegalStateException("Unable to read environments file");
            }
        }

        private Stream<Environment> parse(String line) {
            String[] split = line.split("/");
            String[] clusters = split[2].split(",");
            String[] namespaces = split[3].split(",");

            return Arrays.stream(clusters)
                    .flatMap(cluster -> Arrays.stream(namespaces)
                            .map(ns -> Environment.builder()
                                    .prd("prd".equals(split[0]))
                                    .name(split[1])
                                    .cluster(cluster)
                                    .namespace(Namespace.valueOf(ns.toUpperCase()))
                                    .build()));
        }
    }

    public enum Namespace {
        DEFAULT,
        YCS;

        @Override
        public String toString() {
            return name().toLowerCase();
        }

    }

    @Getter
    private final Set<Environment> allEnvironments = new LinkedHashSet<>();

    private Environments(Collection<Environment> environments) {
        this.allEnvironments.addAll(environments);
    }

    public Environments findEnvironments(String... environmentNames) {
        return findEnvironments(List.of(environmentNames));
    }

    public Environments findEnvironments(Collection<String> environments) {
        return new Environments(allEnvironments.stream()
                .filter(env -> environments.contains(env.getName()))
                .collect(Collectors.toList()));
    }

    public Environments findEnvironments(String name, Namespace namespace) {
        return findEnvironments(List.of(name), List.of(namespace));
    }

    public Environments findEnvironments(Collection<String> environments, Collection<Namespace> namespaces){
        return new Environments(allEnvironments.stream()
                .filter(env -> environments.contains(env.getName()))
                .filter(environment -> namespaces.contains(environment.getNamespace()))
                .collect(Collectors.toList()));
    }

    public boolean isProductionEnvironment() {
        return allEnvironments.stream().allMatch(Environment::isPrd);
    }

    public boolean isDTAEnvironment() {
        return allEnvironments.stream().noneMatch(Environment::isPrd);
    }

    @Override
    public String toString() {
        return allEnvironments.stream().sorted().map(Environment::getPath).collect(Collectors.joining(", "));
    }

    @Override
    public Iterator<Environment> iterator() {
        return allEnvironments.iterator();
    }
}
