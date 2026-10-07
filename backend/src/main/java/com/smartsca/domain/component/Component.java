package com.smartsca.domain.component;
import java.util.Map;

/** Ecosystem-neutral identity; Maven qualifiers are optional metadata. */
public record Component(String purl, String ecosystem, String name, String version, Map<String, String> metadata) {
    public Component { metadata = Map.copyOf(metadata); }
}
