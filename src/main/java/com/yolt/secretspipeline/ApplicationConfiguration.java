package com.yolt.secretspipeline;

import com.yolt.secretspipeline.command.GitlabApiWrapper;
import com.yolt.secretspipeline.command.GitlabEnvironment;
import com.yolt.secretspipeline.command.SecretsPipelineApplicationRunner;
import com.yolt.secretspipeline.command.SecretsPipelineValidatorApplicationRunner;
import com.yolt.secretspipeline.command.io.readers.KustomizeSecretsReader;
import com.yolt.secretspipeline.command.io.readers.SecretsDefinitionReader;
import com.yolt.secretspipeline.command.io.writers.SecretsWriterFactory;
import com.yolt.secretspipeline.generators.SecretDefinitionGenerator;
import com.yolt.secretspipeline.generators.SecretsGenerator;
import com.yolt.secretspipeline.secrets.Environments;
import com.yolt.secretspipeline.vaultrunner.ProcessExecutor;
import com.yolt.secretspipeline.vaultrunner.VaultRunnerHelper;
import com.yolt.secretspipeline.vaultrunner.VaultRunnerHelperCI;
import com.yolt.secretspipeline.vaultrunner.VaultRunnerHelperLocal;
import org.gitlab4j.api.GitLabApi;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import static org.gitlab4j.api.GitLabApi.ApiVersion.V4;

@Configuration
@EnableCaching
public class ApplicationConfiguration {

    @Bean
    public Environments environments() {
        return Environments.AllEnvironments.allEnvironments();
    }

    @Bean
    public GitLabApi gitLabApi(GitlabEnvironment gitlabEnvironment) {
        String gitlabApiToken = gitlabEnvironment.getGitlabApiToken();
        return new GitLabApi(V4, "https://git.yolt.io", gitlabApiToken);
    }

    @Bean
    public GitlabApiWrapper gitlabApiWrapper(GitLabApi gitLabApi, GitlabEnvironment gitlabEnvironment) {
        return new GitlabApiWrapper(gitLabApi, gitlabEnvironment);
    }

    @Bean
    public ProcessExecutor processExecutor() {
        return new ProcessExecutor();
    }

    @Bean
    @Profile("!local")
    public VaultRunnerHelper vaultRunnerHelper(ProcessExecutor processExecutor) {
        return new VaultRunnerHelperCI(processExecutor);
    }

    @Bean
    @Profile("local")
    public VaultRunnerHelper vaultRunnerHelperLocal() {
        return new VaultRunnerHelperLocal();
    }

    @Bean
    public SecretsGenerator secretGenerator(VaultRunnerHelper vaultRunnerHelper) {
        return new SecretsGenerator(vaultRunnerHelper);
    }

    @Bean
    public SecretDefinitionGenerator secretDefinitionGenerator(VaultRunnerHelper vaultRunnerHelper) {
        return new SecretDefinitionGenerator(vaultRunnerHelper);
    }

    @Bean
    public SecretsDefinitionReader secretsDefinitionReader(GitlabApiWrapper gitLabApi) {
        return new SecretsDefinitionReader(gitLabApi);
    }

    @Bean
    public KustomizeSecretsReader secretsReaders(GitlabApiWrapper gitLabApi, Environments environments) {
        return new KustomizeSecretsReader(gitLabApi, environments);
    }

    @Bean
    public SecretsWriterFactory secretsWriters(GitlabApiWrapper gitLabApi, Environments environments) {
        return new SecretsWriterFactory(gitLabApi);
    }

    @Bean
    @Profile("!test")
    public SecretsPipelineApplicationRunner runner(GitlabEnvironment gitlabEnvironment,
                                                   GitlabApiWrapper gitLabApi,
                                                   DiffCollector diffCollector,
                                                   KustomizeSecretsReader secretsReader,
                                                   SecretsWriterFactory secretsWriterFactory,
                                                   SecretDefinitionGenerator secretDefinitionGenerator,
                                                   SecretsGenerator secretGenerator) {
        return new SecretsPipelineApplicationRunner(gitlabEnvironment, gitLabApi, diffCollector, secretsReader, secretsWriterFactory, secretDefinitionGenerator, secretGenerator);
    }

    @Bean
    public SecretsPipelineValidatorApplicationRunner validator(GitLabApi gitLabApi, SecretsDefinitionReader reader, SecretDefinitionGenerator generator, SecretsGenerator secretGenerator) {
        return new SecretsPipelineValidatorApplicationRunner(gitLabApi, reader, generator, secretGenerator);
    }

    @Bean
    public DiffCollector diffCollector(GitlabApiWrapper gitlabApiWrapper, GitlabEnvironment gitlabEnvironment, SecretsDefinitionReader secretsDefinitionReader) {
        return new DiffCollector(gitlabApiWrapper, gitlabEnvironment, secretsDefinitionReader);
    }

}