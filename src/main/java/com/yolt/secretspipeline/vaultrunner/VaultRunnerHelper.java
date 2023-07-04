package com.yolt.secretspipeline.vaultrunner;

import com.yolt.secretspipeline.secrets.Base64String;
import com.yolt.secretspipeline.secrets.VaultString;

public interface VaultRunnerHelper {

    Base64String prdDecryptImportedSecret(VaultString encryptedSecret);

    Base64String dtaDecryptImportedSecret(VaultString encryptedSecret);

    VaultString encryptSecret(Base64String secretToEncrypt, String target);
}