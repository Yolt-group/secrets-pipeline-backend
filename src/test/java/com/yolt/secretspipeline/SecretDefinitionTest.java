package com.yolt.secretspipeline;

import com.yolt.secretspipeline.secrets.Base64String;
import com.yolt.secretspipeline.secrets.SecretDefinition;
import com.yolt.secretspipeline.secrets.SecretType;
import com.yolt.secretspipeline.secrets.VaultString;
import org.junit.jupiter.api.Test;

import static com.yolt.secretspipeline.secrets.Environments.AllEnvironments.allEnvironments;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecretDefinitionTest {

    @Test
    void importedKeyIsTooShort() {
        SecretDefinition definition = defaultSecretDefinition()
                .plaintextSecret(Base64String.encode("encrypted"))
                .importedSecret(VaultString.from("vault:v1:ZW5jcnlwdGVkCg=="))
                .secretType(SecretType.KEY_128)
                .build();

        assertThatThrownBy(definition::validate)
                .hasMessage("The key length of the secret `password` for env: 'dta/team4/cluster2/ycs' does not match the required length. Please consult https://git.yolt.io/security/secrets-pipeline-docker/-/blob/master/src/main/java/com/yolt/secretspipeline/secrets/SecretDefinition.java for the actual checks. Password: 'e*******d'");
    }

    @Test
    void importedPasswordTooShort() {
        SecretDefinition definition = defaultSecretDefinition()
                .plaintextSecret(Base64String.encode("encrypted"))
                .importedSecret(VaultString.from("vault:v1:ZW5jcnlwdGVkCg=="))
                .secretType(SecretType.PASSWORD_ALFA_NUMERIC)
                .build();

        assertThatThrownBy(definition::validate)
                .hasMessage("The key length of the secret `password` for env: 'dta/team4/cluster2/ycs' does not match the required length. Please consult https://git.yolt.io/security/secrets-pipeline-docker/-/blob/master/src/main/java/com/yolt/secretspipeline/secrets/SecretDefinition.java for the actual checks. Password: 'e*******d'");
    }

    @Test
    void importedPasswordTooShortSkipValidationIsOn() {
        SecretDefinition definition = defaultSecretDefinition()
                .plaintextSecret(Base64String.of("dAo"))
                .skipPasswordLengthValidation(true)
                .importedSecret(VaultString.from("vault:v1:ZW5jcnlwdGVkCg=="))
                .secretType(SecretType.PASSWORD_ALFA_NUMERIC)
                .build();

        definition.validate();
    }

    @Test
    void importedPasswordLongerThan12CharactersShouldPass() {
        SecretDefinition definition = defaultSecretDefinition()
                .plaintextSecret(Base64String.of("c2VjcmV0MTIzNHNlY3JldDEyMzQK"))
                .skipPasswordLengthValidation(true)
                .importedSecret(VaultString.from("vault:v1:ZW5jcnlwdGVkCg=="))
                .secretType(SecretType.PASSWORD_ALFA_NUMERIC)
                .build();

        definition.validate();
    }

    @Test
    void importedPasswordCanOnlySkipLengthValidation() {
        SecretDefinition definition = defaultSecretDefinition()
                .plaintextSecret(Base64String.of("c2VjcmV0MTIzNHNlY3JldDEyMzQK"))
                .skipPasswordLengthValidation(true)
                .importedSecret(VaultString.from("vault:v1:ZW5jcnlwdGVkCg=="))
                .secretType(SecretType.KEY_128)
                .build();
        assertThatThrownBy(definition::validate)
                .hasMessage("Skip password length validation can only be used in combination with passwords, please check secret `password`");
    }

    @Test
    void passwordValidationCanOnlyBeSkippedForImportedPassword() {
        SecretDefinition definition = defaultSecretDefinition()
                .plaintextSecret(Base64String.of("dAo"))
                .skipPasswordLengthValidation(true)
                .secretType(SecretType.PASSWORD_ALFA_NUMERIC)
                .build();
        assertThatThrownBy(definition::validate)
                .hasMessage("Skip password can only be used for imported passwords, please check secret `password`");
    }

    @Test
    void maskPassword() {
        Base64String encoded = Base64String.encode("this is the secret");
        String masked = SecretDefinition.maskSecret(encoded);
        assertThat(masked).isEqualTo("t****************t").hasSize(18);
    }

    public SecretDefinition.SecretDefinitionBuilder defaultSecretDefinition() {
        return SecretDefinition.builder()
                .name("password")
                .projectName("test-project")
                .gitlabRepoNamespace("backend")
                .description("imported password")
                .environments(allEnvironments().findEnvironments("team4"));
    }
}