package com.yolt.secretspipeline.command;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
@Getter
public class GitlabEnvironment {

    /**
     * Represents the current logged-in real name
     */
    @Value("${GITLAB_USER_NAME}")
    public String gitlabUserName; // GITLAB_USER_NAME

    /**
     * Represents the current logged-in username
     */
    @Value("${GITLAB_USER_LOGIN}")
    public String gitlabUserLogin; // GITLAB_USER_LOGIN

    /**
     * Represents email address of current logged-in user
     */
    @Value("${GITLAB_USER_EMAIL}")
    public String gitlabUserEmail; // GITLAB_USER_EMAIL

    /**
     * Represents a gitlab api token
     */
    @Value("${GITLAB_API_TOKEN}")
    public String gitlabApiToken; // GITLAB_API_TOKEN

    /**
     * The unique id of the current pipeline that GitLab CI uses internally
     */
    @Value("${CI_PIPELINE_ID}")
    public Integer ciPipelineId; // CI_PIPELINE_ID

    /**
     * The unique id of the current project that GitLab CI uses internally
     */
    @Getter
    @Value("${CI_PROJECT_ID}")
    public Integer ciProjectId; // CI_PROJECT_ID

}
