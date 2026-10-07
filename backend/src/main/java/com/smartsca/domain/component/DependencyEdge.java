package com.smartsca.domain.component;
public record DependencyEdge(String parentPurl, String childPurl, DependencyContext context) {}
