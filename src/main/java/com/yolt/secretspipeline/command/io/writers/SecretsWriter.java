package com.yolt.secretspipeline.command.io.writers;

import com.yolt.secretspipeline.command.io.FileContents;
import com.yolt.secretspipeline.secrets.Secrets;

import java.util.List;

public interface SecretsWriter {

    List<FileContents> writeSecrets(Secrets secrets);
}
