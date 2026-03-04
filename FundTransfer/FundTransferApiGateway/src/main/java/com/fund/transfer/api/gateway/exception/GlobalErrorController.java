package com.fund.transfer.api.gateway.exception;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@Configuration
@Order(-2)
public class GlobalErrorController implements ErrorWebExceptionHandler {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        log.error("Gateway error: {} — {}", ex.getClass().getName(), ex.getMessage());

        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        String code = "GATEWAY_ERROR";
        String message = "An unexpected error occurred";

        // handle specific status exceptions
        if (ex instanceof ResponseStatusException rse) {
            int statusCode = rse.getStatusCode().value();
            status = HttpStatus.resolve(statusCode) != null
                    ? HttpStatus.resolve(statusCode)
                    : HttpStatus.INTERNAL_SERVER_ERROR;

            if (status == HttpStatus.NOT_FOUND) {
                code = "ROUTE_NOT_FOUND";
                message = "The requested endpoint does not exist";
            } else if (status == HttpStatus.UNAUTHORIZED) {
                code = "UNAUTHORIZED";
                message = "Authentication is required";
            } else if (status == HttpStatus.FORBIDDEN) {
                code = "FORBIDDEN";
                message = "You do not have permission to access this resource";
            } else if (status == HttpStatus.SERVICE_UNAVAILABLE) {
                code = "SERVICE_UNAVAILABLE";
                message = "The requested service is temporarily unavailable";
            }
        }

        // handle service down / connection refused
        if (ex instanceof java.net.ConnectException ||
                ex.getClass().getName().contains("ConnectException")) {
            status = HttpStatus.SERVICE_UNAVAILABLE;
            code = "SERVICE_UNAVAILABLE";
            message = "The requested service is temporarily unavailable";
        }

        return createErrorResponse(exchange, status, code, message);
    }

    private Mono<Void> createErrorResponse(ServerWebExchange exchange,
                                           HttpStatus status,
                                           String code,
                                           String message) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("success", false);
        response.put("code", code);
        response.put("message", message);
        response.put("path", exchange.getRequest().getPath().value());
        response.put("timestamp", LocalDateTime.now().toString());

        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        try {
            byte[] bytes = objectMapper.writeValueAsBytes(response);
            return exchange.getResponse().writeWith(
                    Mono.just(exchange.getResponse().bufferFactory().wrap(bytes))
            );
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize error response", e);
            return Mono.error(e);
        }
    }
}