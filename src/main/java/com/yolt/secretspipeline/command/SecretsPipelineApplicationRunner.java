package com.yolt.secretspipeline.command;

import com.yolt.secretspipeline.DiffCollector;
import com.yolt.secretspipeline.command.io.readers.KustomizeSecretsReader;
import com.yolt.secretspipeline.command.io.writers.SecretsWriterFactory;
import com.yolt.secretspipeline.generators.ProjectSecretsGenerator;
import com.yolt.secretspipeline.generators.SecretDefinitionGenerator;
import com.yolt.secretspipeline.generators.SecretsGenerator;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;

import static java.lang.String.format;

@AllArgsConstructor
@Slf4j
public class SecretsPipelineApplicationRunner implements ApplicationRunner {

    public static final String KUSTOMIZE_SECRETS_FILE = "secrets-pipeline.yml";
    public static final int SECRETS_PIPELINE_PROJECT_ID = 878;

    private final GitlabEnvironment gitlabEnvironment;
    private final GitlabApiWrapper gitLab;
    private final DiffCollector diffCollector;
    private final KustomizeSecretsReader secretsReader;
    private final SecretsWriterFactory writers;
    private final SecretDefinitionGenerator secretDefinitionGenerator;
    private final SecretsGenerator secretGenerator;

    @Override
    public void run(ApplicationArguments args) {
        if (args.containsOption("secrets-pipeline")) {
            var pipeline = gitLab.getPipeline(gitlabEnvironment.getCiProjectId(), gitlabEnvironment.getCiPipelineId());
            var mrURL = gitLab.findMergeRequestWhichTriggeredPipeline(SECRETS_PIPELINE_PROJECT_ID, pipeline);
            var options = new Options(args.containsOption("dry-run"), args.containsOption("use-prd-vault"), mrURL);
            var projectSecretsGenerator = new ProjectSecretsGenerator(secretDefinitionGenerator, secretGenerator, options);

            var changedSecretDefinitions = diffCollector.getChanges("secrets", pipeline.getRef());
            if (changedSecretDefinitions.isEmpty()) {
                log.error("No changes detected please check if this is expected");
                return;
            }

            changedSecretDefinitions.groupSecretDefinitionsByProject().forEach((project, definitions) -> {
                var gitlabRepoNamespace = definitions.iterator().next().gitlabRepoNamespace;
                var projectId = gitLab.getProjectIdForTarget(project.getName(), gitlabRepoNamespace);
                var secretsWriter = writers.writer(project, gitlabRepoNamespace);

                var currentSecretsInProject = secretsReader.readSecrets(projectId);
                var secrets = projectSecretsGenerator.update(definitions, currentSecretsInProject);
                var updatedFiles = secretsWriter.writeSecrets(secrets);

                if (updatedFiles.isEmpty()) {
                    log.warn("No secrets were written for any of the environments, check the configuration of the secrets");
                } else if (options.isDryRun()) {
                    log.info("Dry run active, created following secrets:\n");
                    updatedFiles.forEach(file -> log.info("File: {} \n Contents: {} \n", file.getPath(), file.getContents().decode())); //NOSHERIFF path and encrypted secrets are not sensitive
                } else {
                    log.info("Created following secrets:\n");
                    updatedFiles.forEach(file -> log.info("File: {} \n Contents: {} \n", file.getPath(), file.getContents().decode())); //NOSHERIFF path and encrypted secrets are not sensitive
                    var branchName = String.format("secrets_pipeline_%s_%s", options.isUsePRDVault() ? "prd" : "dta", pipeline.getId());
                    var mergeRequestMessage = format("Secrets pipeline: %s ", options.getOriginalMR());
                    gitLab.commitFiles(projectId, branchName, updatedFiles);
                    gitLab.createMergeRequest(projectId, branchName, "master", mergeRequestMessage);
                }
            });
        }
    }
}
