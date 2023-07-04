package com.yolt.secretspipeline.command;

import com.yolt.secretspipeline.DiffCollector;
import com.yolt.secretspipeline.command.io.FileContents;
import com.yolt.secretspipeline.command.io.readers.KustomizeSecretsReader;
import com.yolt.secretspipeline.command.io.writers.SecretsWriterFactory;
import com.yolt.secretspipeline.generators.SecretDefinitionGenerator;
import com.yolt.secretspipeline.generators.SecretsGenerator;
import com.yolt.secretspipeline.secrets.Base64String;
import com.yolt.secretspipeline.secrets.SecretDefinition;
import com.yolt.secretspipeline.secrets.SecretDefinitions;
import com.yolt.secretspipeline.secrets.SecretType;
import com.yolt.secretspipeline.secrets.VaultString;
import com.yolt.secretspipeline.vaultrunner.VaultRunnerHelper;
import org.assertj.core.api.Assertions;
import org.gitlab4j.api.models.Pipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static com.yolt.TestUtil.contains;
import static com.yolt.secretspipeline.command.io.writers.KustomizationYamlWriter.KUSTOMIZATION_FILE_NAME;
import static com.yolt.secretspipeline.secrets.Base64String.encode;
import static com.yolt.secretspipeline.secrets.Environments.AllEnvironments.allEnvironments;
import static java.util.Optional.of;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

@SpringBootTest(args = "--secrets-pipeline")
@ActiveProfiles({"test", "local"})
class SecretsPipelineApplicationRunnerTest {

    @MockBean(answer = Answers.RETURNS_DEEP_STUBS)
    private GitlabEnvironment environment;
    @MockBean
    private GitlabApiWrapper gitlab;
    @MockBean
    private DiffCollector diffCollector;
    @MockBean
    private VaultRunnerHelper vaultRunnerHelper;

    @Autowired
    private KustomizeSecretsReader secretsReader;
    @Autowired
    private SecretsWriterFactory secretsWriterFactory;
    @Autowired
    private SecretDefinitionGenerator secretDefinitionGenerator;
    @Autowired
    private SecretsGenerator secretGenerator;
    @Autowired
    private ApplicationArguments arguments;

    private SecretsPipelineApplicationRunner runner;

    @Captor
    private ArgumentCaptor<List<FileContents>> captor;

    @BeforeEach
    void setup() {
        var pipeline = new Pipeline();
        pipeline.setRef("a036218679fe30fff0dbb96a69f0375ae0ce9783");
        pipeline.setId(982121);
        when(gitlab.getPipeline(any(), any())).thenReturn(pipeline);
        when(gitlab.findMergeRequestWhichTriggeredPipeline(any(), any())).thenReturn("test");
        when(diffCollector.getChanges(any(), any())).thenReturn(new SecretDefinitions(List.of()));
        runner = new SecretsPipelineApplicationRunner(environment, gitlab, diffCollector, secretsReader, secretsWriterFactory, secretDefinitionGenerator, secretGenerator);
    }

    @Test
    void noChanges() {
        assertDoesNotThrow(() -> runner.run(arguments));
    }

    @Test
    @DisplayName("When a secret definition for 1 project only that project should receive a merge request")
    void forOneProject() {
        String kustomizationWithout = """
            apiVersion: kustomize.config.k8s.io/v1beta1
            kind: Kustomization
            namespace: default
            bases:
              - ../../base
            patchesStrategicMerge:
              - config-map.yaml
            vars:
            """;

        when(vaultRunnerHelper.encryptSecret(any(), any())).thenReturn(VaultString.from("vault:v1:test"));
        when(gitlab.getFile(any(), eq("k8s/env/dta/team4/cluster2/ycs/kustomization.yaml"), eq("master")))
                .thenReturn(of(encode(kustomizationWithout).getBase64()));

        var definition = SecretDefinition.builder()
                .name("key")
                .description("a test key")
                .projectName("test")
                .gitlabRepoNamespace("test-namespace")
                .rotate(true)
                .plaintextSecret(Base64String.encode("mysecret"))
                .secretType(SecretType.KEY_128)
                .environments(allEnvironments().findEnvironments("team4"))
                .build();
        when(diffCollector.getChanges(any(), any())).thenReturn(new SecretDefinitions(List.of(definition)));

        runner.run(arguments);

        Mockito.verify(gitlab).commitFiles(any(), any(), captor.capture());
        var files = captor.getValue();

        var expectedContents = """
                apiVersion: apps/v1
                kind: Deployment
                metadata:
                  name: test
                spec:
                  template:
                    metadata:
                      annotations:
                        vault.hashicorp.com/agent-inject-secret-key: ""
                        vault.hashicorp.com/agent-inject-template-key: |
                          {{- with secret "transit/git/decrypt/team4-ycs-test" "ciphertext=vault:v1:test" "context=eW9sdC1naXQtc3RvcmFnZQo=" -}}
                          type: KEY_128
                          {{ .Data.plaintext }}
                          {{- end -}}
                """;
        var expectedContents2 = """
            apiVersion: kustomize.config.k8s.io/v1beta1
            kind: Kustomization
            namespace: default
            bases:
              - ../../base
            patchesStrategicMerge:
              - secrets-pipeline.yml
              - config-map.yaml
            vars:
                """;
        Assertions.assertThat(files)
                .hasSize(2)
                .contains(
                        new FileContents("k8s/env/dta/team4/cluster2/ycs/secrets-pipeline.yml", Base64String.encode(expectedContents)),
                        new FileContents("k8s/env/dta/team4/cluster2/ycs/kustomization.yaml", Base64String.encode(expectedContents2))
                );

        Mockito.verify(gitlab).createMergeRequest(0, "secrets_pipeline_dta_982121", "master", "Secrets pipeline: test ");
    }

    @Test
    @DisplayName("When a secret definition and dry run is set to true no commits should be executed")
    void dryRunIsOn() {
        when(vaultRunnerHelper.encryptSecret(any(), any())).thenReturn(VaultString.from("vault:v1:test"));
        var definition = SecretDefinition.builder()
                .name("key")
                .description("a test key")
                .projectName("test")
                .gitlabRepoNamespace("test-namespace")
                .rotate(true)
                .plaintextSecret(Base64String.encode("mysecret"))
                .secretType(SecretType.KEY_128)
                .environments(allEnvironments().findEnvironments("team4"))
                .build();
        when(diffCollector.getChanges(any(), any())).thenReturn(new SecretDefinitions(List.of(definition)));

        var arguments = new DefaultApplicationArguments("--secrets-pipeline, --dryRun");
        runner.run(arguments);

        Mockito.verify(gitlab, times(0)).commitFiles(any(), any(), any());
    }

    @Test
    @DisplayName("When a secret definition for multiple projects then multiple merge requests should be create")
    void multipleProjects() {
        when(vaultRunnerHelper.encryptSecret(any(), any())).thenReturn(VaultString.from("vault:v1:test"));
        when(gitlab.getFile(any(), eq("k8s/env/dta/team4/cluster2/ycs/kustomization.yaml"), eq("master")))
                .thenReturn(of(encode("some config").getBase64()));

        var definition1 = SecretDefinition.builder()
                .name("key")
                .description("a test key")
                .projectName("api-gw")
                .gitlabRepoNamespace("test-namespace")
                .rotate(true)
                .plaintextSecret(Base64String.encode("mysecret"))
                .secretType(SecretType.KEY_128)
                .environments(allEnvironments().findEnvironments("team4"))
                .build();
        var definition2 = SecretDefinition.builder()
                .name("key")
                .projectName("partners")
                .gitlabRepoNamespace("test-namespace")
                .description("a test secret")
                .rotate(true)
                .plaintextSecret(Base64String.encode("mysecret"))
                .secretType(SecretType.KEY_128)
                .environments(allEnvironments().findEnvironments("team4"))
                .build();
        when(diffCollector.getChanges(any(), any())).thenReturn(new SecretDefinitions(List.of(definition1, definition2)));

        runner.run(arguments);

        Mockito.verify(gitlab, times(2)).commitFiles(any(), any(), any());
        Mockito.verify(gitlab, times(2)).createMergeRequest(anyInt(), any(), any(), any());
    }

    @Test
    @DisplayName("Given a secret definition for a Kustomize project when the pipeline runs then a secrets file Kustomize format should be created")
    void projectUsingKustomize() {
        var kustomizationFileInEnv = """
            apiVersion: kustomize.config.k8s.io/v1beta1
            kind: Kustomization
            namespace: default
            bases:
              - ../../base
            patchesStrategicMerge:
              - config-map.yaml
            vars:
            """;
        when(gitlab.getProjectIdForTarget(any(), any())).thenReturn(1);
        when(gitlab.fileExists(1, "k8s/base/kustomization.yaml", "master")).thenReturn(true);
        when(gitlab.getFile(1, "k8s/env/dta/team4/cluster2/ycs/" + KUSTOMIZATION_FILE_NAME, "master")).thenReturn(of(Base64String.encode(kustomizationFileInEnv).toString()));
        when(vaultRunnerHelper.encryptSecret(any(), any())).thenReturn(VaultString.from("vault:v1:test"));
        var definition = SecretDefinition.builder()
                .name("key")
                .description("a test key")
                .projectName("test")
                .gitlabRepoNamespace("test-namespace")
                .rotate(true)
                .plaintextSecret(Base64String.encode("mysecret"))
                .secretType(SecretType.KEY_128)
                .environments(allEnvironments().findEnvironments("team4"))
                .build();
        when(diffCollector.getChanges(any(), any())).thenReturn(new SecretDefinitions(List.of(definition)));

        runner.run(arguments);

        Mockito.verify(gitlab).commitFiles(any(), any(), captor.capture());
        var files = captor.getValue();

        var expectedContents = """
                apiVersion: apps/v1
                kind: Deployment
                metadata:
                  name: test
                spec:
                  template:
                    metadata:
                      annotations:
                        vault.hashicorp.com/agent-inject-secret-key: ""
                        vault.hashicorp.com/agent-inject-template-key: |
                          {{- with secret "transit/git/decrypt/team4-ycs-test" "ciphertext=vault:v1:test" "context=eW9sdC1naXQtc3RvcmFnZQo=" -}}
                          type: KEY_128
                          {{ .Data.plaintext }}
                          {{- end -}}
                """;
        Assertions.assertThat(files)
                .filteredOn(f -> f.getPath().contains("secrets-pipeline.yml"))
                .first()
                .extracting(FileContents::getContents)
                .has(contains(expectedContents));
        //Did we update the kustomization to add the secrets-pipeline.yml file
        Assertions.assertThat(files)
                .filteredOn(f -> f.getPath().contains("kustomization.yaml"))
                .first()
                .extracting(FileContents::getContents)
                .has(contains(" - secrets-pipeline.yml"));

        Mockito.verify(gitlab).createMergeRequest(1, "secrets_pipeline_dta_982121", "master", "Secrets pipeline: test ");
    }
}