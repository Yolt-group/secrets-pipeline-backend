package com.yolt.secretspipeline.command.io.writers;

import com.yolt.secretspipeline.command.GitlabApiWrapper;
import com.yolt.secretspipeline.command.io.FileContents;
import com.yolt.secretspipeline.secrets.Base64String;
import com.yolt.secretspipeline.secrets.Secrets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static com.yolt.TestUtil.contains;
import static com.yolt.TestUtil.endsWith;
import static com.yolt.TestUtil.startsWith;
import static com.yolt.secretspipeline.command.io.writers.KustomizationYamlWriter.KUSTOMIZATION_FILE_NAME;
import static com.yolt.secretspipeline.secrets.Base64String.encode;
import static java.util.Optional.of;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KustomizationYamlWriterTest {

    private final SecretsWriter secretsWriter = secrets -> List.of(
            new FileContents("test/secrets-pipeline.yml", Base64String.encode("test"))
    );

    private final int projectId = 1;

    private final String kustomizationIncomplete = """
            \n\n
            apiVersion: kustomize.config.k8s.io/v1beta1
            kind: Kustomization
            namespace: default
            bases:
              - ../../base
            vars:
            
            """;
    private final String kustomizationWithout = """
            \n\n
            apiVersion: kustomize.config.k8s.io/v1beta1
            kind: Kustomization
            namespace: default
            bases:
              - ../../base
            patchesStrategicMerge:
              - config-map.yaml
            vars:
            """;
    private final String kustomizationWith = """
            apiVersion: kustomize.config.k8s.io/v1beta1
            kind: Kustomization
            namespace: default
            bases:
              - ../../base
            patchesStrategicMerge:
              - config-map.yaml
              - secrets-pipeline.yml
            vars:
            """;

    @Mock
    private GitlabApiWrapper gitlabApiWrapper;

    private KustomizationYamlWriter kustomizationYamlWriter;

    @BeforeEach
    void setup() {
        kustomizationYamlWriter = new KustomizationYamlWriter(secretsWriter, gitlabApiWrapper, projectId);
    }

    @Test
    void shouldAddSecretsFileReferenceIfNotYetPresent() {
        when(gitlabApiWrapper.getFile(projectId, "test/" + KUSTOMIZATION_FILE_NAME, "master"))
                .thenReturn(of(encode(kustomizationWithout).getBase64()));

        var files = kustomizationYamlWriter.writeSecrets(new Secrets(List.of()));

        assertThat(files)
                .filteredOn(f -> f.getPath().contains(KUSTOMIZATION_FILE_NAME))
                .first()
                .extracting(FileContents::getContents)
                .has(contains("  - secrets-pipeline.yml"))
                .has(endsWith("\n"))
                .has(startsWith("apiVersion"));
    }

    @Test
    void shouldNotAddSecretsFileReferenceAgainIfAlreadyPresent() {
        when(gitlabApiWrapper.getFile(projectId, "test/" + KUSTOMIZATION_FILE_NAME, "master"))
                .thenReturn(of(encode(kustomizationWith).getBase64()));

        var files = kustomizationYamlWriter.writeSecrets(new Secrets(List.of()));

        assertThat(files).hasSize(1);
    }

    @Test
    void shouldPatchesStrategicMergeSectionIfMissing() {
        when(gitlabApiWrapper.getFile(projectId, "test/" + KUSTOMIZATION_FILE_NAME, "master"))
                .thenReturn(of(encode(kustomizationIncomplete).getBase64()));

        var files = kustomizationYamlWriter.writeSecrets(new Secrets(List.of()));

        assertThat(files)
                .filteredOn(f -> f.getPath().contains(KUSTOMIZATION_FILE_NAME))
                .first()
                .extracting(FileContents::getContents)
                .has(contains("patchesStrategicMerge:\n  - secrets-pipeline.yml"))
                .has(endsWith("\n"))
                .has(startsWith("apiVersion"));
    }

    @Test
    void fileNotPresentInGitlabShouldNotUpdate() {
        var files = kustomizationYamlWriter.writeSecrets(new Secrets(List.of()));
        assertThat(files).isEmpty();
    }
}
