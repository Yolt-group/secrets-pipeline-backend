package com.yolt.secretspipeline.command.io.writers;

import com.yolt.secretspipeline.command.GitlabApiWrapper;
import com.yolt.secretspipeline.command.io.FileContents;
import com.yolt.secretspipeline.secrets.Base64String;
import com.yolt.secretspipeline.secrets.Secrets;
import lombok.RequiredArgsConstructor;
import org.apache.commons.io.IOUtils;
import org.eclipse.jgit.lib.Constants;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static com.yolt.secretspipeline.command.SecretsPipelineApplicationRunner.KUSTOMIZE_SECRETS_FILE;
import static java.util.stream.Collectors.toList;

@RequiredArgsConstructor
public class KustomizationYamlWriter implements SecretsWriter {

    public static final String KUSTOMIZATION_FILE_NAME = "kustomization.yaml";
    private final SecretsWriter secretsWriter;
    private final GitlabApiWrapper gitlabApiWrapper;
    private final Integer projectId;

    @Override
    public List<FileContents> writeSecrets(Secrets secrets) {
        List<FileContents> secretFiles = this.secretsWriter.writeSecrets(secrets);
        return mergeIntoKustomizeFiles(secretFiles);
    }

    /**
     * Extend kustomization.yaml with:
     *
     * <pre>
     * patchesStrategicMerge:
     *   - config-map.yaml
     *   - secrets-pipeline.yml
     * </pre>
     */
    private List<FileContents> mergeIntoKustomizeFiles(List<FileContents> k8sSecrets) {
        return k8sSecrets.stream()
                .flatMap(k8sSecret -> {
                    // Filter secrets for clusters that do not have a kustomization.yml
                    // Do not use .filter because gitlabApiWrapper.getFile can be slow
                    var fileName = k8sSecret.getPath().replace(KUSTOMIZE_SECRETS_FILE, KUSTOMIZATION_FILE_NAME);
                    Optional<String> kustomizationYml = gitlabApiWrapper.getFile(projectId, fileName, Constants.MASTER);
                    // File does not exist, don't add secrets for this cluster
                    if (kustomizationYml.isEmpty()) {
                        return Stream.empty();
                    }
                    // File does exist, add secrets
                    return kustomizationYml
                            .flatMap(kustomizeFile -> addSecretsFileToStrategicMerge(fileName, kustomizeFile))
                            .map(changedKustomizeFile -> Stream.of(k8sSecret, changedKustomizeFile))
                            .orElseGet(() -> Stream.of(k8sSecret));
                }).collect(toList());
    }

    private Optional<FileContents> addSecretsFileToStrategicMerge(String fileName, String base64FileContents) {
        var fileContents = new String(Base64.getDecoder().decode(base64FileContents)).trim();
        try {
            if (!fileContents.contains(KUSTOMIZE_SECRETS_FILE)) {
                var sw = new StringWriter();
                var pw = new PrintWriter(sw);
                List<String> lines = IOUtils.readLines(new StringReader(fileContents));

                boolean added = false;

                for (var line : lines) {
                    pw.println(line);
                    if (line.startsWith("patchesStrategicMerge:")) {
                        pw.println("  - " + KUSTOMIZE_SECRETS_FILE);
                        added = true;
                    }
                }
                if (!added) {
                    pw.println("patchesStrategicMerge:");
                    pw.println("  - " + KUSTOMIZE_SECRETS_FILE);
                }
                return Optional.of(new FileContents(fileName, Base64String.encode(sw.toString())));
            }
        } catch (IOException e) {
            //ignore
        }
        return Optional.empty();
    }

}
