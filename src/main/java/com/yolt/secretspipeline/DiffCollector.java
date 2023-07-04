package com.yolt.secretspipeline;

import com.yolt.secretspipeline.command.GitlabApiWrapper;
import com.yolt.secretspipeline.command.GitlabEnvironment;
import com.yolt.secretspipeline.command.io.readers.SecretsDefinitionReader;
import com.yolt.secretspipeline.secrets.SecretDefinitions;
import org.apache.commons.io.FilenameUtils;
import org.gitlab4j.api.models.Diff;

import java.util.List;
import java.util.stream.Collectors;

public class DiffCollector {

    private final GitlabApiWrapper gitlab;
    private final GitlabEnvironment gitlabEnvironment;
    private final SecretsDefinitionReader reader;

    public DiffCollector(GitlabApiWrapper gitlab, GitlabEnvironment gitlabEnvironment, SecretsDefinitionReader reader) {
        this.gitlab = gitlab;
        this.gitlabEnvironment = gitlabEnvironment;
        this.reader = reader;
    }

    public SecretDefinitions getChanges(String filePath, String ref) {
        var changes = gitlab.getDiffs(gitlabEnvironment.ciProjectId, gitlabEnvironment.ciPipelineId);

        return reader.readSecretsDefinitions(getDiffsRelatedToSecretDefinitions(filePath, changes), ref);
    }

    private List<String> getDiffsRelatedToSecretDefinitions(String filePath, List<Diff> diffs) {
        return diffs.stream()
                .filter(d -> !d.getDeletedFile())
                .map(Diff::getNewPath) //new_path is also present when dealing with deleted file
                .filter(path -> path.startsWith(filePath))
                .filter(path -> FilenameUtils.getExtension(path).equals("json"))
                .collect(Collectors.toList());
    }
}
