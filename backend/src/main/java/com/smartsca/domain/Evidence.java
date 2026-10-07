package com.smartsca.domain;

import java.time.Instant;
import java.util.Objects;

/** Source observation; cached observations retain their original collection time. */
public record Evidence<T>(String source, Instant collectedAt, String sourceDate,
                          EvidenceStatus status, T value, String diagnostic) {
    public Evidence {
        Objects.requireNonNull(source);
        Objects.requireNonNull(collectedAt);
        Objects.requireNonNull(status);
        if ((status == EvidenceStatus.DISPONIBLE) != (value != null))
            throw new IllegalArgumentException("Solo la evidencia disponible tiene valor.");
    }
    /** Copy a collection at the typed snapshot boundary without changing an inferred concrete T. */
    public Evidence<T> copyValue(java.util.function.UnaryOperator<T> copy) {
        return new Evidence<>(source, collectedAt, sourceDate, status, value == null ? null : copy.apply(value), diagnostic);
    }
    public static <T> Evidence<T> available(String source, Instant time, String date, T value) {
        return new Evidence<>(source, time, date, EvidenceStatus.DISPONIBLE, value, null);
    }
    public static <T> Evidence<T> absent(String source, EvidenceStatus status, String reason) {
        return new Evidence<>(source, Instant.now(), null, status, null, reason);
    }
}
