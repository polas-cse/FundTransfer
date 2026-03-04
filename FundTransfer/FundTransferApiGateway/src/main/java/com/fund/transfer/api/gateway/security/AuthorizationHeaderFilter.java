package com.fund.transfer.api.gateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;

@Slf4j
@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    @Autowired
    Environment env;

    public AuthorizationHeaderFilter() {
        super(Config.class);
    }

    public static class Config {}

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            try {
                ServerHttpRequest request = exchange.getRequest();

                log.info("Gateway Filter - Processing request: {}", request.getPath());

                // check Authorization header exists
                if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    log.warn("No authorization header for path: {}", request.getPath());
                    return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
                }

                String authorizationHeader = request.getHeaders()
                        .get(HttpHeaders.AUTHORIZATION).get(0);

                // check Bearer format
                if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
                    log.warn("Invalid authorization header format for path: {}", request.getPath());
                    return onError(exchange, "Invalid authorization header format", HttpStatus.UNAUTHORIZED);
                }

                String jwt = authorizationHeader.replace("Bearer ", "");

                // validate JWT
                if (!isJwtValid(jwt)) {
                    log.warn("Invalid JWT token for path: {}", request.getPath());
                    return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
                }

                Claims claims = extractClaims(jwt);
                Long userId = claims.get("userId", Long.class);
                String username = claims.getSubject();

                // guard against null claims
                if (userId == null || username == null) {
                    log.warn("JWT claims missing userId or username");
                    return onError(exchange, "Invalid token claims", HttpStatus.UNAUTHORIZED);
                }

                log.info("JWT valid — userId: {}, username: {}", userId, username);

                // forward user info to downstream services
                ServerHttpRequest modifiedRequest = request.mutate()
                        .header("X-User-Id", userId.toString())
                        .header("X-User-Name", username)
                        .build();

                return chain.filter(exchange.mutate().request(modifiedRequest).build());

            } catch (Exception e) {
                log.error("Gateway Filter Exception: {} — {}", e.getClass().getName(), e.getMessage(), e);
                return onError(exchange, "Authentication error", HttpStatus.INTERNAL_SERVER_ERROR);
                // don't expose e.getMessage() to client — security risk
            }
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        response.getHeaders().add("Content-Type", "application/json");

        log.warn("Sending error response: {} (Status: {})", err, httpStatus);

        // structured JSON error response
        String jsonError = String.format(
                "{\"success\":false,\"code\":\"%s\",\"message\":\"%s\",\"timestamp\":\"%s\"}",
                httpStatus.name(),
                err,
                LocalDateTime.now()
        );

        DataBufferFactory bufferFactory = response.bufferFactory();
        DataBuffer dataBuffer = bufferFactory.wrap(jsonError.getBytes(StandardCharsets.UTF_8));

        return response.writeWith(Mono.just(dataBuffer));
    }

    private boolean isJwtValid(String jwt) {
        try {
            String tokenSecret = env.getProperty("jwt.secret");

            if (tokenSecret == null || tokenSecret.isBlank()) {
                log.error("JWT secret is null or empty");
                return false;
            }

            SecretKey signingKey = Keys.hmacShaKeyFor(
                    tokenSecret.getBytes(StandardCharsets.UTF_8));

            Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(jwt);

            return true;

        } catch (Exception ex) {
            log.warn("JWT validation failed: {} — {}", ex.getClass().getName(), ex.getMessage());
            return false;
        }
    }

    private Claims extractClaims(String jwt) {
        String tokenSecret = env.getProperty("jwt.secret");
        SecretKey signingKey = Keys.hmacShaKeyFor(
                tokenSecret.getBytes(StandardCharsets.UTF_8));

        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
    }
}