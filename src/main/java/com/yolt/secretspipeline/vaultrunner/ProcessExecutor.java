package com.yolt.secretspipeline.vaultrunner;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Slf4j
public class ProcessExecutor {

    public String execWithoutOutputToConsole(List<String> command) throws IOException {
        try {
            var process = runProcess(new ProcessBuilder().command(command));
            if (process.exitValue() == 0) {
                return StringUtils.chomp(IOUtils.toString(process.getInputStream(), StandardCharsets.UTF_8).trim());
            }
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Vault command failed", e);
        }
        throw new IOException("Vault command failed");
    }

    private Process runProcess(ProcessBuilder builder) throws InterruptedException, IOException {
        var process = builder.start();
        process.waitFor();
        return process;
    }
}
