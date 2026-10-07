package com.smartsca.domain.component;

/** Maven scope and effective scope along this module's path. */
public record DependencyContext(String module, String originalScope, String normalizedContext) {}
