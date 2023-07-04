FROM 627987680837.dkr.ecr.eu-central-1.amazonaws.com/prd/sre/vault-runner-helper:v1.5.0 AS base
FROM openjdk:15-slim-buster@sha256:1e069bf1c5c23adde58b29b82281b862e473d698ce7cc4e164194a0a2a1c044a

ENV JAVA_TOOL_OPTIONS='-Djavax.net.ssl.trustStore=/usr/local/openjdk-15/lib/security/cacerts -Djavax.net.ssl.trustStorePassword=changeit'

# Copy vault-runner-helper from base image
COPY --from=base /usr/local/bin/vault-runner-helper /usr/local/bin/
COPY --from=base /usr/local/bin/vault /usr/local/bin/

COPY target/secrets-pipeline-1.0-SNAPSHOT.jar /secrets-pipeline.jar
