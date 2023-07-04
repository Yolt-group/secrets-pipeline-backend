package com.yolt.secretspipeline.vaultrunner;

import com.yolt.secretspipeline.secrets.Base64String;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class VaultRunnerHelperCITest {

    @Mock
    private ProcessExecutor processExecutor;

    @InjectMocks
    private VaultRunnerHelperCI vaultRunnerHelper;

    @Captor
    private ArgumentCaptor<List<String>> listArgumentCaptor;

    @BeforeEach
    void setUp() throws IOException {
        Mockito.doReturn("vault:v1:test").when(processExecutor).execWithoutOutputToConsole(listArgumentCaptor.capture());
    }

    @Test
    @DisplayName("When encrypting plaintext with PRD Vault it should be called with right command")
    void encryptPRD_shouldBuildProperCommand() {
        vaultRunnerHelper.encryptSecret(Base64String.encode("test"), "yfb-prd-ycs-site-management");

        String joinedCommand = String.join(" ", listArgumentCaptor.getValue());

        assertThat(joinedCommand).isEqualTo("vault-runner-helper encrypt -key yfb-prd-ycs-site-management -skip-validation dGVzdA==");
    }

    @Test
    @DisplayName("When encrypting plaintext with DTA Vault it should be called with right command")
    void encryptDTA_shouldBuildProperCommand() {
        vaultRunnerHelper.encryptSecret(Base64String.encode("test"), "team4-ycs-site-management");

        String joinedCommand = String.join(" ", listArgumentCaptor.getValue());

        assertThat(joinedCommand).isEqualTo("vault-runner-helper encrypt -key team4-ycs-site-management -skip-validation dGVzdA==");
    }

}
