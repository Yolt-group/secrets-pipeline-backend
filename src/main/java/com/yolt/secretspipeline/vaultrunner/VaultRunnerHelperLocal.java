package com.yolt.secretspipeline.vaultrunner;

import com.yolt.secretspipeline.secrets.Base64String;
import com.yolt.secretspipeline.secrets.VaultString;
import org.apache.commons.lang3.RandomStringUtils;

public class VaultRunnerHelperLocal implements VaultRunnerHelper {

    @Override
    public VaultString encryptSecret(Base64String secretToEncrypt, String target) {
        return VaultString.from("vault:v1:" + Base64String.encode(RandomStringUtils.randomAlphabetic(20)));
    }

    @Override
    public Base64String dtaDecryptImportedSecret(VaultString encryptedSecret) {
        return Base64String.of("UmV0dXJuIHZhbHVlIGZyb20gVmF1bHRIZWxwZXJMb2NhbAo=");
    }

    @Override
    public Base64String prdDecryptImportedSecret(VaultString encryptedSecret) {
        return dtaDecryptImportedSecret(encryptedSecret);
    }
}
