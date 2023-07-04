package com.yolt.secretspipeline.secrets;

import lombok.EqualsAndHashCode;
import lombok.Getter;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Getter
@EqualsAndHashCode
public class Base64String {

    private final String base64;

    private Base64String(String base64) {
        this.base64 = base64;
    }

    public static Base64String of(String base64) {
        return new Base64String(base64);
    }

    public static Base64String encode(String str) {
        return new Base64String(Base64.getEncoder().encodeToString(str.getBytes(StandardCharsets.UTF_8)));
    }

    public static Base64String encode(byte[] b) {
        return new Base64String(Base64.getEncoder().encodeToString(b));
    }

    public String decode() {
        return new String(Base64.getDecoder().decode(base64));
    }

    @Override
    public String toString() {
        return base64;
    }

    public int lengthRawBytes() {
        return Base64.getDecoder().decode(base64).length;
    }
}
