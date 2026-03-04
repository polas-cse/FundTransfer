package com.fund.transfer.api.gateway.exception;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.handler.ResponseStatusExceptionHandler;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

@Configuration
@Order(-2)
public class GlobalErrorController extends ResponseStatusExceptionHandler {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        // Check if the exception is a NotFoundException (404)
        if (ex.getClass().getSimpleName().contains("NotFoundException") || 
            ex instanceof org.springframework.web.server.ResponseStatusException) {
            return createErrorResponse(exchange, ex);
        }
        
        return super.handle(exchange, ex);
    }

    private Mono<Void> createErrorResponse(ServerWebExchange exchange, Throwable ex) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("code", "ROUTE_NOT_FOUND");
        response.put("message", "The requested endpoint does not exist. Please verify your request URL and HTTP method.");
        response.put("path", exchange.getRequest().getPath().value());
        response.put("timestamp", System.currentTimeMillis());
        
        exchange.getResponse().setStatusCode(HttpStatus.NOT_FOUND);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        
        try {
            byte[] bytes = objectMapper.writeValueAsBytes(response);
            return exchange.getResponse().writeWith(
                    Mono.just(exchange.getResponse().bufferFactory().wrap(bytes))
            );
        } catch (JsonProcessingException e) {
            return Mono.error(e);
        }
    }
}
