package com.yolt.secretspipeline.command.io.writers;

import com.yolt.secretspipeline.command.io.FileContents;
import com.yolt.secretspipeline.secrets.Base64String;
import com.yolt.secretspipeline.secrets.Environment;
import com.yolt.secretspipeline.secrets.Secret;
import com.yolt.secretspipeline.secrets.SecretType;
import com.yolt.secretspipeline.secrets.Secrets;
import lombok.RequiredArgsConstructor;
import org.springframework.util.StringUtils;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

import static com.yolt.secretspipeline.command.SecretsPipelineApplicationRunner.KUSTOMIZE_SECRETS_FILE;

@RequiredArgsConstructor
public class KustomizeSecretsWriter implements SecretsWriter {

    private static final String HEADER = """
            apiVersion: apps/v1
            kind: Deployment
            metadata:
              name: %s
            spec:
              template:
                metadata:
                  annotations:
            """;
    private final String projectName;

    @Override
    public List<FileContents> writeSecrets(Secrets secrets) {
        var files = new ArrayList<FileContents>();
        var secretsPerEnvironment = secrets.groupByEnvironment();
        secretsPerEnvironment.forEach((key, value) -> {
            var contents = write(value);
            if (StringUtils.hasText(contents)) {
                var secretFile = createOrUpdateFile(key, String.format(HEADER, projectName) + contents);
                files.add(secretFile);
            }
        });

        return files;
    }

    private String write(List<Secret> secrets) {
        secrets.sort(Comparator.comparing(s -> s.secretName));
        return secrets.stream()
                .filter(secret -> secret.vaultPath.contains(secret.environment.getName() + "-" + secret.environment.getNamespace()))
                .map(this::createInjectorTemplate).collect(Collectors.joining(""));
    }

    private String createInjectorTemplate(Secret secret) {
        var sw = new StringWriter();
        var pw = new PrintWriter(sw);
        pw.println("        vault.hashicorp.com/agent-inject-secret-" + secret.secretName + ": \"\"");
        pw.println("        vault.hashicorp.com/agent-inject-template-" + secret.secretName + ": |");
        pw.println("          {{- with secret \"transit/git/decrypt/" + secret.vaultPath + "\" \"ciphertext=" + secret.content + "\" \"context=eW9sdC1naXQtc3RvcmFnZQo=\" -}}");
        pw.println("          type: " + secret.getSecretType());
        pw.println("          {{ .Data.plaintext }}");

        if (secret.secretType.isAsymmetric() && secret.secretType != SecretType.GPG) {
            pw.println("          ----------");
            pw.println("          " + secret.publicKeyOrCertContent);
        }
        pw.println("          {{- end -}}");
        return sw.toString();
    }

    private FileContents createOrUpdateFile(Environment environment, String contents) {
        var path = String.format("k8s/env/%s/%s/%s/%s/%s",
                environment.isPrd() ? "prd" : "dta",
                environment.getName(),
                environment.getCluster(),
                environment.getNamespace().toString().toLowerCase(),
                KUSTOMIZE_SECRETS_FILE
        );
        return new FileContents(path, Base64String.encode(contents));
    }
}
