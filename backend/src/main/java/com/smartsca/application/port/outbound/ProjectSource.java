package com.smartsca.application.port.outbound;

import com.smartsca.domain.analysis.AnalysisConfiguration;
import com.smartsca.domain.analysis.Project;
import java.util.List;
import java.io.InputStream;
import java.nio.file.Path;

/** Resolve authorized catalog identities rather than arbitrary user paths. */
public interface ProjectSource {
    List<Project> listProjects();
    Project validate(String projectId, AnalysisConfiguration configuration);
    void snapshot(Project project, AnalysisConfiguration configuration, Path destination);
    default Project importZip(InputStream input, String filename) { throw new UnsupportedOperationException("Catálogo de solo lectura."); }
    default Project importGit(String url) { throw new UnsupportedOperationException("Catálogo de solo lectura."); }
    final class ImportBusyException extends IllegalStateException {
        public ImportBusyException() { super("Hay una importación en curso. Inténtalo de nuevo al terminar."); }
    }
    final class ImportStorageException extends IllegalStateException {
        public ImportStorageException() { super("No se pudo acceder al almacenamiento de proyectos importados."); }
    }
}
