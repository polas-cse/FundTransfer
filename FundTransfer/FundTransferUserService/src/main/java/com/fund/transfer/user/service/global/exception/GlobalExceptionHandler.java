package com.fund.transfer.user.service.global.exception;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;
import org.springframework.web.server.ServerWebInputException;
import reactor.core.publisher.Mono;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @Value("${spring.profiles.active:prod}")
    private String activeProfile;

    @ExceptionHandler(ApiException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleApiException(ApiException ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("success", false);
        body.put("code", ex.getCode());
        body.put("message", ex.getMessage());
        body.put("timestamp", LocalDateTime.now());

        return Mono.just(ResponseEntity.badRequest().body(body));
    }

    // handles @Valid failures on @RequestBody
    @ExceptionHandler(WebExchangeBindException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleValidationErrors(WebExchangeBindException ex) {
        Map<String, String> errors = new LinkedHashMap<>();

        ex.getBindingResult().getFieldErrors()
                .forEach(err -> errors.put(err.getField(), err.getDefaultMessage()));

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", false);
        body.put("code", "VALIDATION_ERROR");
        body.put("errors", errors);
        body.put("timestamp", LocalDateTime.now());

        return Mono.just(ResponseEntity.badRequest().body(body));
    }

    // handles malformed JSON / wrong types in request body
    @ExceptionHandler(ServerWebInputException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleInputError(ServerWebInputException ex) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", false);
        body.put("code", "INVALID_INPUT");
        body.put("message", "Malformed or invalid request body");
        body.put("timestamp", LocalDateTime.now());

        return Mono.just(ResponseEntity.badRequest().body(body));
    }

    @ExceptionHandler(Exception.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleGeneric(Exception ex) {
        System.err.println("========================================");
        System.err.println(" EXCEPTION CAUGHT IN USER SERVICE");
        System.err.println(" Type: " + ex.getClass().getName());
        System.err.println(" Message: " + ex.getMessage());
        System.err.println("========================================");
        ex.printStackTrace();
        System.err.println("========================================");

        Map<String, Object> body = new HashMap<>();
        body.put("success", false);
        body.put("code", "INTERNAL_ERROR");
        body.put("message", ex.getMessage() != null ? ex.getMessage() : "Something went wrong");
        body.put("exceptionType", ex.getClass().getSimpleName());
        body.put("timestamp", LocalDateTime.now());

        if (isDevelopmentMode()) {
            body.put("stackTrace", getStackTraceAsString(ex));
        }

        return Mono.just(ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(body));
    }

    // reads from application.properties instead of hardcoded true
    private boolean isDevelopmentMode() {
        return "dev".equalsIgnoreCase(activeProfile) || "local".equalsIgnoreCase(activeProfile);
    }

    private String getStackTraceAsString(Exception ex) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        ex.printStackTrace(pw);
        return sw.toString();
    }
}