package com.yolt.secretspipeline;

import com.yolt.secretspipeline.secrets.UnixEpoch;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.temporal.ChronoUnit;

class UnixEpochTest {

    @Test
    void tooLargeValueShouldBeRejected() {
        Assertions.assertThatThrownBy(() -> new UnixEpoch(23423423423423234L)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void duration() {
        UnixEpoch u = new UnixEpoch().plus(1, ChronoUnit.SECONDS);

        Assertions.assertThat(u.duration()).isEqualTo(1);
    }

    @Test
    void date() {
        UnixEpoch u = new UnixEpoch();

        Assertions.assertThat(u.toDate().toString()).containsPattern("\\d{4}-\\d{2}-\\d{2}");
    }

    @Test
    void plus() {
        UnixEpoch u = new UnixEpoch();
        u = u.plus(1, ChronoUnit.DAYS);

        Assertions.assertThat(u.duration()).isEqualTo(86400L);
    }

}