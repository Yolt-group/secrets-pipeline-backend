package com.yolt;

import com.yolt.secretspipeline.secrets.Base64String;
import lombok.experimental.UtilityClass;
import org.assertj.core.api.Condition;

@UtilityClass
public class TestUtil {

    public static Condition<Base64String> contains(String expected) {
        return new Condition<>() {
            public boolean matches(Base64String contents) {
                return contents.decode().contains(expected);
            }
        };
    }

    public static Condition<Base64String> endsWith(String expected) {
        return new Condition<>() {
            public boolean matches(Base64String contents) {
                return contents.decode().endsWith(expected);
            }
        };
    }

    public static Condition<Base64String> startsWith(String expected) {
        return new Condition<>() {
            public boolean matches(Base64String contents) {
                return contents.decode().startsWith(expected);
            }
        };
    }
}
