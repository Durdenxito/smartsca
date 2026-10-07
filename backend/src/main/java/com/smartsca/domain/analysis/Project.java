package com.smartsca.domain.analysis;

/** A catalog identity and the reference recorded when a request is created. */
public record Project(String id, String name, String sourceReference, String analyzedReference,
                      java.util.Set<String> modules, java.util.Set<String> profiles) {
    public Project {
        modules = java.util.Set.copyOf(modules);
        profiles = java.util.Set.copyOf(profiles);
    }
}
