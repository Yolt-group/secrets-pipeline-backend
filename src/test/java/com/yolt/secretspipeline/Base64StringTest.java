package com.yolt.secretspipeline;

import com.yolt.secretspipeline.secrets.VaultString;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class Base64StringTest {

    @Test
    void base64ShouldNotAddNewLine() {
        assertThat(VaultString.from("vault:v1:48vlqSDk7HRiDLAQGIq36uCQTeuTXa/4KL7sS9dLXK8=")).hasToString("vault:v1:48vlqSDk7HRiDLAQGIq36uCQTeuTXa/4KL7sS9dLXK8=");
        assertThat(VaultString.from("vault:v1:48vlqSDk7HRiDLAQGIq36uCQTeuTXa/4KL7sS9dLXK8=").getBase64String()).hasToString("48vlqSDk7HRiDLAQGIq36uCQTeuTXa/4KL7sS9dLXK8=");
    }
}