package com.fund.transfer.user.service.global.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import reactor.core.publisher.Mono;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ApiException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleApiException(ApiException ex) {

        Map<String, Object> body = new HashMap<>();
        body.put("success", false);
        body.put("code", ex.getCode());
        body.put("message", ex.getMessage());
        body.put("timestamp", LocalDateTime.now());

        return Mono.just(ResponseEntity
                .badRequest()
                .body(body));
    }

    @ExceptionHandler(Exception.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleGeneric(Exception ex) {

        System.err.println("========================================");
        System.err.println("❌ EXCEPTION CAUGHT IN USER SERVICE");
        System.err.println("❌ Type: " + ex.getClass().getName());
        System.err.println("❌ Message: " + ex.getMessage());
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

    private boolean isDevelopmentMode() {
        return true;
    }

    private String getStackTraceAsString(Exception ex) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        ex.printStackTrace(pw);
        return sw.toString();
    }
}