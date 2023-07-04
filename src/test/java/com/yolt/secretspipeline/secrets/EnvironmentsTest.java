package com.yolt.secretspipeline.secrets;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class EnvironmentsTest {
    @Test
    @DisplayName("When environment is dta then asking if it is a dta env should return true")
    void checkDTAvsDTAEnv() {
        var environment = Environments.AllEnvironments.allEnvironments().findEnvironments("team4");

        assertThat(environment.isDTAEnvironment()).isTrue();
    }

    @Test
    @DisplayName("When environment is prd then asking if it is a prd env should return true")
    void checkPRDvsPRDEnv() {
        var environment = Environments.AllEnvironments.allEnvironments().findEnvironments("yfb-ext-prd");

        assertThat(environment.isProductionEnvironment()).isTrue();
    }

    @Test
    @DisplayName("When environment is dta then asking if it is a prd env should return false")
    void checkPRDvsDTAEnv() {
        var environment = Environments.AllEnvironments.allEnvironments().findEnvironments("team4");

        assertThat(environment.isProductionEnvironment()).isFalse();
    }

    @Test
    void findMultipleEnvironments() {
        var environments = Environments.AllEnvironments.allEnvironments().findEnvironments("team5", "team6");

        assertThat(environments).hasSize(2);
    }
}