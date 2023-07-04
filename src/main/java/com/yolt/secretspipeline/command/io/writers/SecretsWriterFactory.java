package com.yolt.secretspipeline.command.io.writers;

import com.yolt.secretspipeline.command.GitlabApiWrapper;
import com.yolt.secretspipeline.secrets.Project;

public class SecretsWriterFactory {

    private final GitlabApiWrapper gitlabApiWrapper;

    public SecretsWriterFactory(GitlabApiWrapper gitlabApiWrapper) {
        this.gitlabApiWrapper = gitlabApiWrapper;
    }

    public SecretsWriter writer(Project project, String namespace) {
        var projectId = gitlabApiWrapper.getProjectIdForTarget(project.getName(), namespace);
        return new KustomizationYamlWriter(new KustomizeSecretsWriter(project.getName()), gitlabApiWrapper, projectId);
    }
}
