package com.smartsca.adapter.inbound.rest;

import com.smartsca.application.port.inbound.GetAnalysisUseCase;
import com.smartsca.application.port.inbound.StartAnalysisUseCase;
import com.smartsca.domain.analysis.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.net.URI;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/** HTTP catalog, asynchronous registration acknowledgement and persisted status queries. */
@RestController @RequestMapping("/api")
public class AnalysisController {
    private final StartAnalysisUseCase start;
    private final GetAnalysisUseCase query;
    public AnalysisController(StartAnalysisUseCase start, GetAnalysisUseCase query) { this.start = start; this.query = query; }

    public record Catalog(List<Project> projects, AnalysisConfiguration defaults, List<String> scopes) {}
    public record StartRequest(@NotBlank @Size(max = 64) @Pattern(regexp = "[a-z0-9][a-z0-9-]{0,63}") String projectId,
                               AnalysisConfiguration configuration) {}
    public record Accepted(UUID id, AnalysisStatus status) {}

    @GetMapping("/projects") public Catalog projects() {
        return new Catalog(start.listProjects(), AnalysisConfiguration.defaults(), AnalysisConfiguration.SUPPORTED_SCOPES.stream().sorted().toList());
    }
    @PostMapping("/analyses") public ResponseEntity<Accepted> register(@Valid @RequestBody StartRequest request) {
        UUID id = start.start(request.projectId(), request.configuration());
        return ResponseEntity.accepted().location(URI.create("/api/analyses/" + id)).body(new Accepted(id, AnalysisStatus.EN_COLA));
    }
    @GetMapping("/analyses/{id}") public Analysis get(@PathVariable UUID id) { return query.get(id); }
    @GetMapping("/analyses/{id}/components") public List<GetAnalysisUseCase.ComponentItem> components(@PathVariable UUID id,
            @RequestParam(required = false) String search, @RequestParam(required = false) String module,
            @RequestParam(required = false) String scope, @RequestParam(required = false) Boolean direct) {
        return query.components(id, search, module, scope, direct);
    }
    @GetMapping("/analyses/{id}/graph") public com.smartsca.domain.component.DependencyGraph.Neighborhood graph(@PathVariable UUID id,
            @RequestParam String module, @RequestParam(required = false) String purl, @RequestParam(defaultValue = "0") int offset) {
        return query.graph(id, module, purl, offset);
    }
    @GetMapping("/analyses/{id}/routes") public com.smartsca.domain.component.DependencyGraph.Routes routes(@PathVariable UUID id,
            @RequestParam String purl, @RequestParam(required = false) String module, @RequestParam(defaultValue = "0") int offset) {
        return query.routes(id, purl, module, offset);
    }
}
