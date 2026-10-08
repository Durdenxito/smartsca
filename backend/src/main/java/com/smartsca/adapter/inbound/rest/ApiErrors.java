package com.smartsca.adapter.inbound.rest;

import java.util.NoSuchElementException;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

/** Public errors contain actionable messages rather than internal paths or database details. */
@RestControllerAdvice
public class ApiErrors {
    @ExceptionHandler(com.smartsca.application.port.outbound.ProjectSource.ImportBusyException.class)
    ProblemDetail importBusy(Exception error) { return ProblemDetail.forStatusAndDetail(HttpStatus.TOO_MANY_REQUESTS, error.getMessage()); }
    @ExceptionHandler(com.smartsca.application.port.outbound.ProjectSource.ImportStorageException.class)
    ProblemDetail importStorage(Exception error) { return ProblemDetail.forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE, error.getMessage()); }
    @ExceptionHandler(org.springframework.web.multipart.MaxUploadSizeExceededException.class)
    ProblemDetail oversized(Exception error) { return ProblemDetail.forStatusAndDetail(HttpStatus.PAYLOAD_TOO_LARGE, "ZIP demasiado grande: máximo 10 MiB."); }
    @ExceptionHandler(org.springframework.web.multipart.MultipartException.class)
    ProblemDetail multipart(Exception error) { return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Selecciona un archivo ZIP válido."); }
    @ExceptionHandler(com.smartsca.application.port.inbound.ExportAnalysisUseCase.ArtifactUnavailableException.class)
    ProblemDetail artifactUnavailable(Exception error) { return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, error.getMessage()); }
    @ExceptionHandler(IllegalArgumentException.class)
    ProblemDetail invalid(IllegalArgumentException error) { return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, error.getMessage()); }
    @ExceptionHandler({HttpMessageNotReadableException.class, MethodArgumentNotValidException.class, MethodArgumentTypeMismatchException.class,
        MissingServletRequestParameterException.class, org.springframework.web.multipart.support.MissingServletRequestPartException.class})
    ProblemDetail malformed(Exception error) { return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Solicitud no válida. Revisa el proyecto, el identificador y la configuración."); }
    @ExceptionHandler(NoSuchElementException.class)
    ProblemDetail missing(NoSuchElementException error) { return ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, "El análisis no existe."); }
    @ExceptionHandler(DataAccessException.class)
    ProblemDetail unavailable(DataAccessException error) { return ProblemDetail.forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE, "No se pudo acceder al almacenamiento. Inténtalo de nuevo."); }
    @ExceptionHandler(Exception.class)
    ProblemDetail unexpected(Exception error) { return ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "No se pudo completar la solicitud."); }
}
