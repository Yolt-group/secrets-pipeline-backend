package com.yolt.secretspipeline.command.io.readers;

import antlr4.VaultBaseListener;
import antlr4.VaultLexer;
import antlr4.VaultParser;
import com.yolt.secretspipeline.command.GitlabApiWrapper;
import com.yolt.secretspipeline.secrets.Base64String;
import com.yolt.secretspipeline.secrets.Environment;
import com.yolt.secretspipeline.secrets.Environments;
import com.yolt.secretspipeline.secrets.Secret;
import com.yolt.secretspipeline.secrets.SecretType;
import com.yolt.secretspipeline.secrets.Secrets;
import com.yolt.secretspipeline.secrets.VaultString;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.antlr.v4.runtime.BaseErrorListener;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.RecognitionException;
import org.antlr.v4.runtime.Recognizer;
import org.antlr.v4.runtime.tree.ParseTree;
import org.antlr.v4.runtime.tree.ParseTreeWalker;

import java.util.ArrayDeque;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.yolt.secretspipeline.command.SecretsPipelineApplicationRunner.KUSTOMIZE_SECRETS_FILE;

@Slf4j
@RequiredArgsConstructor
public class KustomizeSecretsReader {

    private final GitlabApiWrapper gitlabApi;
    private final Environments environments;

    public Secrets readSecrets(Integer projectId) {
        Set<Secret> secrets = environments.getAllEnvironments()
                .stream()
                .flatMap((Environment environment) -> readSecretsForEnvironment(environment, projectId))
                .collect(Collectors.toSet());
        return new Secrets(secrets);
    }

    private Stream<Secret> readSecretsForEnvironment(Environment environment, Integer projectId) {
        var dir = environment.getPath();
        return gitlabApi.getFile(projectId, "k8s/env/" + dir + "/" + KUSTOMIZE_SECRETS_FILE, "master")
                .stream()
                .map(file -> Base64String.of(file).decode())
                .map(this::removeK8sAnnotations)
                .flatMap(this::readSecrets)
                .map(builder -> builder.environment(environment).build());
    }

    private String removeK8sAnnotations(String file) {
        return file.lines().dropWhile(line -> !line.trim().contains("vault.hashicorp.com/agent-inject")).collect(Collectors.joining("\n"));
    }

    @SuppressWarnings("ConstantConditions")
    private Stream<Secret.SecretBuilder> readSecrets(String contents) {
        VaultParser parser = initParser(contents);
        ParseTree tree = parser.start();

        if (parser.getNumberOfSyntaxErrors() > 0) {
            throw new IllegalStateException("Unable to parse the Vault annotations");
        }

        var builders = new ArrayDeque<Secret.SecretBuilder>();
        ParseTreeWalker.DEFAULT.walk(new VaultBaseListener() {

            @Override
            public void enterPath(VaultParser.PathContext ctx) {
                builders.peek().vaultPath(ctx.getText().substring(ctx.getText().lastIndexOf("/") + 1));
            }

            @Override
            public void enterBase64PublicPart(VaultParser.Base64PublicPartContext ctx) {
                builders.peek().publicKeyOrCertContent(Base64String.of(ctx.getText()));
            }

            @Override
            public void enterSecretTypeIndicator(VaultParser.SecretTypeIndicatorContext ctx) {
                builders.peek().secretType(SecretType.valueOf(ctx.getText()));
            }

            @Override
            public void enterVaultCipherText(VaultParser.VaultCipherTextContext ctx) {
                builders.peek().content(VaultString.from(ctx.getText()));
            }

            @Override
            public void enterTemplateName(VaultParser.TemplateNameContext ctx) {
                builders.push(Secret.builder());
                builders.peek().secretName(ctx.getText());
            }
        }, tree);

        return builders.stream();
    }


    private VaultParser initParser(String secretsFile) {
        var lexer = new VaultLexer(CharStreams.fromString(secretsFile));
        var parser = new VaultParser(new CommonTokenStream(lexer));

        parser.setBuildParseTree(true);
        parser.addErrorListener(new BaseErrorListener() {
            @Override
            public void syntaxError(Recognizer<?, ?> recognizer, Object offendingSymbol, int line, int charPositionInLine, String msg, RecognitionException e) {
                log.error("line {}:{} {}", line, charPositionInLine, msg);
            }
        });

        return parser;
    }
}