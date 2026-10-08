package com.smartsca.domain.analysis;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;

/** Validated JSON bytes and their integrity metadata, stored apart from the analysis response. */
public record AnalysisArtifact(String schemaVersion, Instant generatedAt, String sha256, String content) {
    public static final int MAX_BYTES = 16 * 1024 * 1024;
    public AnalysisArtifact {
        Objects.requireNonNull(generatedAt);
        if (!"1.6".equals(schemaVersion) || content == null || content.isBlank()
                || content.length() > MAX_BYTES || content.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES
                || !digest(content).equals(sha256)) throw new IllegalArgumentException("Artefacto SBOM no íntegro o no admitido.");
    }
    public static String digest(String content) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content.getBytes(StandardCharsets.UTF_8))); }
        catch (java.security.NoSuchAlgorithmException error) { throw new IllegalStateException(error); }
    }
}
