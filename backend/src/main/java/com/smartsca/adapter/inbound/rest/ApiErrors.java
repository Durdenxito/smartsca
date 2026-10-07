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
    @ExceptionHandler(IllegalArgumentException.class)
    ProblemDetail invalid(IllegalArgumentException error) { return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, error.getMessage()); }
    @ExceptionHandler({HttpMessageNotReadableException.class, MethodArgumentNotValidException.class, MethodArgumentTypeMismatchException.class,
        MissingServletRequestParameterException.class})
    ProblemDetail malformed(Exception error) { return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Solicitud no válida. Revisa el proyecto, el identificador y la configuración."); }
    @ExceptionHandler(NoSuchElementException.class)
    ProblemDetail missing(NoSuchElementException error) { return ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, "El análisis no existe."); }
    @ExceptionHandler(DataAccessException.class)
    ProblemDetail unavailable(DataAccessException error) { return ProblemDetail.forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE, "No se pudo acceder al almacenamiento. Inténtalo de nuevo."); }
    @ExceptionHandler(Exception.class)
    ProblemDetail unexpected(Exception error) { return ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "No se pudo completar la solicitud."); }
}
