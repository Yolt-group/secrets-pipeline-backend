package com.yolt.secretspipeline.vaultrunner;

import com.yolt.secretspipeline.secrets.Base64String;
import com.yolt.secretspipeline.secrets.VaultString;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class VaultRunnerHelperCI implements VaultRunnerHelper {

    private static final String ENCRYPT_VALUE = "encrypt";
    private static final String DECRYPT_VALUE = "decrypt";

    private final ProcessExecutor processExecutor;

    public Base64String prdDecryptImportedSecret(final VaultString encryptedSecret) {
        return decryptImportedSecret(encryptedSecret, "prd-provisioner");
    }

    public Base64String dtaDecryptImportedSecret(final VaultString encryptedSecret) {
        return decryptImportedSecret(encryptedSecret, "dta-provisioner");
    }

    private Base64String decryptImportedSecret(final VaultString encryptedSecret, final String vaultPath) {
        var decryptCommand = List.of(
                "vault-runner-helper",
                DECRYPT_VALUE,
                "-key",
                vaultPath,
                encryptedSecret.toString());
        try {
            return Base64String.of(processExecutor.execWithoutOutputToConsole(decryptCommand));
        } catch (IOException e) {
            throw new IllegalStateException("Unable to decrypt secret for path '" + vaultPath + "'");
        }
    }

    public VaultString encryptSecret(final Base64String secretToEncrypt, final String vaultPath) {
        var encryptCommand = List.of(
                "vault-runner-helper",
                ENCRYPT_VALUE,
                "-key",
                vaultPath,
                "-skip-validation",
                secretToEncrypt.getBase64());
        try {
            return VaultString.from(processExecutor.execWithoutOutputToConsole(encryptCommand));
        } catch (IOException e) {
            throw new IllegalStateException("Unable to encrypt secret for path '" + vaultPath + "'");
        }

    }
}
