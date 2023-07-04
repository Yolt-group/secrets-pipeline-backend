package com.yolt.secretspipeline.command;

import com.yolt.secretspipeline.command.io.readers.SecretsDefinitionReader;
import com.yolt.secretspipeline.generators.SecretDefinitionGenerator;
import com.yolt.secretspipeline.generators.SecretsGenerator;
import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FilenameUtils;
import org.eclipse.jgit.lib.Constants;
import org.gitlab4j.api.GitLabApi;
import org.gitlab4j.api.models.TreeItem;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;

import java.util.stream.Collectors;

@AllArgsConstructor
@Slf4j
public class SecretsPipelineValidatorApplicationRunner implements ApplicationRunner {

    public static final int SECRETS_PIPELINE_PROJECT_ID = 878;

    private final GitLabApi gitLab;
    private final SecretsDefinitionReader secretsDefinitionReader;
    private final SecretDefinitionGenerator generator;
    private final SecretsGenerator secretGenerator;

    @SneakyThrows
    @Override
    public void run(ApplicationArguments args) {
        if (args.containsOption("validate")) {
            var branch = args.getOptionValues("branch").stream().findFirst().orElse(Constants.MASTER);
            var tree = this.gitLab.getRepositoryApi().getTree(SECRETS_PIPELINE_PROJECT_ID, "secrets", branch, true);
            var fileNames = tree.stream()
                    .filter(item -> item.getType() == TreeItem.Type.BLOB)
                    .filter(item -> FilenameUtils.getExtension(item.getName()).equals("json"))
                    .map(TreeItem::getPath)
                    .collect(Collectors.toList());
            var secretDefinitions = secretsDefinitionReader
                    .readSecretsDefinitions(fileNames, branch)
                    .filterDTAEnvironments();

            secretDefinitions.groupSecretDefinitionsByProject().forEach((p, s) -> {
                var extendedDefinitions = generator.extendWithRealSecret(s);
                secretGenerator.secretDefinitionsToSecrets(extendedDefinitions);
            });
        }
    }
}
