package com.yolt.secretspipeline.secrets;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.time.Clock;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.TemporalUnit;

@Getter
@EqualsAndHashCode
@ToString
public class UnixEpoch {

    /**
     * The limitation is due to PGP otherwise the key info will not be added in the PGP key
     */
    private static final Long MAX_VALUE = 4294967296L;
    private static final Clock utcClock = Clock.systemUTC();
    private final Long epoch;

    public UnixEpoch() {
        this(LocalDateTime.now(utcClock).toEpochSecond(ZoneOffset.UTC));
    }

    public UnixEpoch(Long epoch) {
        if (epoch > MAX_VALUE) {
            throw new IllegalArgumentException("The maximum value is: " + MAX_VALUE + " received " + epoch);
        }

        this.epoch = epoch;
    }

    public UnixEpoch plus(int amount, TemporalUnit unit) {
        return new UnixEpoch(LocalDateTime.ofEpochSecond(epoch, 0, ZoneOffset.UTC).plus(amount, unit).toEpochSecond(ZoneOffset.UTC));
    }

    public Long duration() {
        return Math.abs(LocalDateTime.now(utcClock).toEpochSecond(ZoneOffset.UTC) - epoch);
    }

    public LocalDate toDate() {
        return LocalDateTime.ofEpochSecond(epoch, 0, ZoneOffset.UTC).toLocalDate();
    }
}
