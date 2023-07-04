# Secrets-pipeline-docker

Backend to support the secrets-pipeline.

# Development

Before importing the project first run: `mvn compile` to compile the ANTLR grammar for reading the secrets from the Vault annotations.

## Parsing Vault annotations

For reading the Vault annotations like:

```
 vault.hashicorp.com/agent-inject-template-push.android.api.key: |
   {{- with secret "transit/git/decrypt/team4-ycs-site-management" "ciphertext=vault:v1:HAX7DRt=" -}}
   type: PASSWORD_ALFA_NUMERIC_SPECIAL_CHARS
   {{ .Data.plaintext }}
   {{- end -}}
```

an ANTLR parser is used (see https://www.antlr.org/) and it used in the `KustomizeSecretsReader` this way we can easily parse the annotations without resorting to String grepping etc.

# Run locally 

You can run it locally to test the full roundtrip including creating the merge requests. You will not be able to actually interact with `vault-helper-runner` for this a mock implementation has been provided.

Run `Application` with the following parameters:

Environment variables:
```
GITLAB_USER_NAME=
GITLAB_USER_LOGIN=
GITLAB_USER_EMAIL=
GITLAB_API_TOKEN=
CI_PIPELINE_ID=
CI_PROJECT_ID=878
```

- The first three can be obtained by: https://git.yolt.io/api/v4/users?username=<<username>>
- `CI_PIPELINE_ID` can be retrieved from: https://git.yolt.io/security/secrets-pipeline/-/pipelines
- The api token only needs read-access.

If you pass `--dry-run` as argument only the secrets will be generated and no commits/merge requests will be created. Also make sure to enable the `local` Spring Boot profile.

