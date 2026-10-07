package com.smartsca.domain.analysis;

import java.util.Set;

/** Immutable, bounded configuration; the project source checks which selections it supports. */
public record AnalysisConfiguration(Set<String> modules, Set<String> profiles, Set<String> scopes,
                                    String environmentId, String declaredDeployment) {
    public static final Set<String> SUPPORTED_SCOPES = Set.of("compile", "runtime", "test", "provided");

    public AnalysisConfiguration {
        modules = checked(modules, false);
        profiles = checked(profiles, true);
        scopes = checked(scopes, false);
        if (!SUPPORTED_SCOPES.containsAll(scopes)) throw new IllegalArgumentException("Scope no admitido.");
        if (environmentId == null || environmentId.isBlank() || environmentId.length() > 64)
            throw new IllegalArgumentException("Entorno no válido.");
        if (declaredDeployment != null) {
            declaredDeployment = declaredDeployment.strip();
            if (declaredDeployment.length() > 500) throw new IllegalArgumentException("El contexto admite hasta 500 caracteres.");
            if (declaredDeployment.isEmpty()) declaredDeployment = null;
        }
    }

    private static Set<String> checked(Set<String> values, boolean allowEmpty) {
        if (values == null || (!allowEmpty && values.isEmpty()) || values.size() > 32
                || values.stream().anyMatch(v -> v == null || v.isBlank() || v.length() > 128))
            throw new IllegalArgumentException("Configuración no válida.");
        return Set.copyOf(values);
    }

    /** Configuration currently admitted for the initial single-module fixture. */
    public static AnalysisConfiguration defaults() {
        return new AnalysisConfiguration(Set.of("."), Set.of(), Set.of("compile", "runtime"), "java-21", null);
    }
}
