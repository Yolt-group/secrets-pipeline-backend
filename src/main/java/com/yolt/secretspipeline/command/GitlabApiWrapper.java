package com.yolt.secretspipeline.command;

import com.yolt.secretspipeline.command.io.FileContents;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.gitlab4j.api.Constants;
import org.gitlab4j.api.GitLabApi;
import org.gitlab4j.api.GitLabApiException;
import org.gitlab4j.api.models.CommitAction;
import org.gitlab4j.api.models.Diff;
import org.gitlab4j.api.models.MergeRequest;
import org.gitlab4j.api.models.Pipeline;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.util.CollectionUtils;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.eclipse.jgit.lib.Constants.MASTER;

@Slf4j
@RequiredArgsConstructor
public class GitlabApiWrapper {

    private final GitLabApi gitLabApi;
    private final GitlabEnvironment gitlabEnvironment;

    @SneakyThrows
    @Cacheable(cacheNames = "pipelines")
    public Pipeline getPipeline(Integer projectId, Integer pipelineId) {
        return gitLabApi.getPipelineApi().getPipeline(projectId, pipelineId);
    }

    @SneakyThrows
    public List<Diff> getDiffs(Integer projectId, Integer pipelineId) {
        var pipeline = gitLabApi.getPipelineApi().getPipeline(projectId, pipelineId);

        var branchName = pipeline.getRef();
        if (MASTER.equals(branchName)) {
            return gitLabApi.getRepositoryApi().compare(projectId, pipeline.getBeforeSha(), pipeline.getSha()).getDiffs();
        } else {
            return gitLabApi.getRepositoryApi().compare(projectId, MASTER, pipeline.getSha()).getDiffs();
        }
    }

    @SneakyThrows
    @Cacheable(cacheNames = "projectIds")
    public int getProjectIdForTarget(String projectName, String namespace) {
        return gitLabApi.getProjectApi().getProject(namespace, projectName).getId();
    }

    @Cacheable(cacheNames = "files")
    public boolean fileExists(Integer projectId, String name, String ref) {
        try {
            gitLabApi.getRepositoryFileApi().getFile(projectId, name, ref);
            return true;
        } catch (GitLabApiException e) {
            return false;
        }
    }

    public Optional<String> getFile(Integer projectId, String file, String ref) {
        try {
            return Optional.of(this.gitLabApi.getRepositoryFileApi().getFile(projectId, file, ref).getContent());
        } catch (GitLabApiException e) {
            return Optional.empty();
        }
    }

    private CommitAction createCommitAction(Integer projectId, String path, String base64EncodedContent) {
        boolean alreadyExists = getFile(projectId, path, MASTER).isPresent();
        var commitAction = new CommitAction();
        commitAction.setAction(alreadyExists ? CommitAction.Action.UPDATE : CommitAction.Action.CREATE);
        commitAction.setContent(base64EncodedContent);
        commitAction.setFilePath(path);
        commitAction.setEncoding(Constants.Encoding.BASE64);
        return commitAction;
    }

    @SneakyThrows
    public void commitFiles(Integer projectId, String sourceBranchName, List<FileContents> files) {
        var commitActions = files.stream()
                .map(f -> createCommitAction(projectId, f.getPath(), f.getContents().toString()))
                .collect(Collectors.toList());
        gitLabApi.getCommitsApi().createCommit(
                projectId,
                sourceBranchName,
                "Update secrets",
                MASTER,
                gitlabEnvironment.gitlabUserName,
                gitlabEnvironment.gitlabUserEmail,
                commitActions
        );
    }

    @SneakyThrows
    public void createMergeRequest(final int projectId, final String sourceBranch, final String targetBranch, String message) {
        MergeRequest mergeRequest;
        mergeRequest = gitLabApi.getMergeRequestApi().createMergeRequest(projectId, sourceBranch, targetBranch, message, "", null, null, null, null, true, true);
        log.info("Merge-request for source-branch {} to target-branch {} available at {}", sourceBranch, targetBranch, mergeRequest.getWebUrl());
    }

    @SneakyThrows
    public String findMergeRequestWhichTriggeredPipeline(final Integer projectId, Pipeline pipeline) {
        List<String> parents = gitLabApi.getCommitsApi().getCommit(projectId, pipeline.getSha()).getParentIds();
        if (!CollectionUtils.isEmpty(parents)) {
            Collections.reverse(parents);
            List<MergeRequest> mergeRequests = gitLabApi.getCommitsApi().getMergeRequests(projectId, parents.get(0));
            if (!CollectionUtils.isEmpty(mergeRequests)) {
                return mergeRequests.get(0).getWebUrl();
            }
        }
        return "Unknown MR";
    }
}
