package com.yolt.secretspipeline.secrets;

import lombok.EqualsAndHashCode;
import lombok.Getter;

@Getter
@EqualsAndHashCode
public class VaultString {

    private final String vaultVersion;
    private final Base64String base64String;

    private VaultString(String vaultVersion, Base64String base64) {
        this.vaultVersion = vaultVersion;
        base64String = base64;
    }

    @Override
    public String toString() {
        return vaultVersion + ":" + base64String.getBase64();
    }

    public static VaultString from(String vaultString) {
        return new VaultString(vaultString.substring(0, vaultString.lastIndexOf(":")), Base64String.of(vaultString.substring(vaultString.lastIndexOf(":") + 1)));
    }
}
