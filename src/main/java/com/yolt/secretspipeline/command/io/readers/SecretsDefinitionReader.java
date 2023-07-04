package com.yolt.secretspipeline.command.io.readers;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yolt.secretspipeline.command.GitlabApiWrapper;
import com.yolt.secretspipeline.secrets.Base64String;
import com.yolt.secretspipeline.secrets.Environments;
import com.yolt.secretspipeline.secrets.SecretDefinition;
import com.yolt.secretspipeline.secrets.SecretDefinitions;
import com.yolt.secretspipeline.secrets.UnixEpoch;
import com.yolt.secretspipeline.secrets.VaultString;
import lombok.SneakyThrows;
import org.apache.commons.io.FilenameUtils;

import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import static com.yolt.secretspipeline.command.SecretsPipelineApplicationRunner.SECRETS_PIPELINE_PROJECT_ID;
import static com.yolt.secretspipeline.secrets.Environments.AllEnvironments.allEnvironments;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;
import static org.springframework.util.StringUtils.hasText;

public class SecretsDefinitionReader {

    private final GitlabApiWrapper gitLabApi;

    public SecretsDefinitionReader(GitlabApiWrapper gitLabApi) {
        this.gitLabApi = gitLabApi;
    }

    public SecretDefinitions readSecretsDefinitions(List<String> files, String ref) {
        var definitions = files.stream()
                .map(f -> readSecretsDefinition(f, ref))
                .flatMap(Collection::stream)
                .collect(toList());

        return new SecretDefinitions(definitions);
    }

    @SneakyThrows
    private Set<SecretDefinition> readSecretsDefinition(String file, String ref) {
        var project = FilenameUtils.getName(FilenameUtils.getFullPathNoEndSeparator(file));
        var base64Contents = gitLabApi.getFile(SECRETS_PIPELINE_PROJECT_ID, file, ref)
                .orElseThrow(() -> new IllegalStateException("File " + file + " not found."));
        byte[] fileContents = Base64.getDecoder().decode(base64Contents);

        var mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        var definitions = mapper.readValue(fileContents, new TypeReference<List<JsonSecretDefinition>>() {
        });
        return definitions.stream()
                .map(jsonSecretDefinition -> mapTo(jsonSecretDefinition, project))
                .collect(toSet());
    }

    private SecretDefinition mapTo(JsonSecretDefinition json, String project) {
        return SecretDefinition.builder()
                .projectName(project)
                .name(json.name)
                .environments(mapTo(json.name, json.environments, json.namespaces))
                .importedSecret(hasText(json.importedSecret) ? VaultString.from(json.importedSecret) : null)
                .publicKeyOrCert(hasText(json.publicKeyOrCert) ? Base64String.of(json.publicKeyOrCert) : null)
                .gitlabRepoNamespace(json.gitlabRepoNamespace)
                .skipPasswordLengthValidation(json.skipPasswordLengthValidation)
                .secretType(json.secretType)
                .description(json.description)
                .rotate(json.rotate)
                .validTilUnixEpoch(json.validTilUnixEpoch != null ? new UnixEpoch(json.validTilUnixEpoch) : null)
                .csrTemplate(json.csrTemplate)
                .jwksTemplate(json.jwksTemplate)
                .pgpTemplate(json.pgpTemplate)
                .build();
    }

    private Environments mapTo(String name, Set<String> environments, Set<String> namespacesAsStrings) {
        var namespaces = namespacesAsStrings.stream()
                .map(String::toUpperCase)
                .map(Environments.Namespace::valueOf)
                .collect(toList());

        var selectedEnvironments = allEnvironments().findEnvironments(environments, namespaces);

        if (selectedEnvironments.getAllEnvironments().isEmpty()) {
            throw new IllegalArgumentException("Secret definition: " + name + " does not resolve to any valid environments(" + environments + ", " + namespacesAsStrings + ")");
        }
        return selectedEnvironments;
    }
}
