package com.yolt.secretspipeline.generators;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

public class ErrorCollector<T> {

    @Getter
    @AllArgsConstructor
    public class SecretsProcessingError {
        @NonNull
        private final Exception originalException;
        @NonNull
        private final T originalObject;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            SecretsProcessingError that = (SecretsProcessingError) o;
            return Objects.equals(originalException.getMessage(), that.originalException.getMessage()) && Objects.equals(originalObject, that.originalObject);
        }

        @Override
        public int hashCode() {
            return Objects.hash(originalException.getMessage(), originalObject);
        }
    }

    @Getter
    private final List<SecretsProcessingError> errors = new ArrayList<>();

    public void trySafe(Consumer<T> consumer, T t) {
        try {
            consumer.accept(t);
        } catch (Exception e) {
            errors.add(new SecretsProcessingError(e, t));
        }
    }

    public boolean hasErrors() {
        return !errors.isEmpty();
    }
}
