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
public class AuthorizationHeaderFilter
        extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

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

                log.info("Gateway Filter - Processing: {}", request.getPath());

                // check Authorization header
                if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    log.warn("No authorization header for path: {}", request.getPath());
                    return onError(exchange, "No authorization header",
                            HttpStatus.UNAUTHORIZED);
                }

                String authHeader = request.getHeaders()
                        .get(HttpHeaders.AUTHORIZATION).get(0);

                if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                    log.warn("Invalid authorization header format");
                    return onError(exchange, "Invalid authorization header format",
                            HttpStatus.UNAUTHORIZED);
                }

                String jwt = authHeader.replace("Bearer ", "");

                if (!isJwtValid(jwt)) {
                    log.warn("Invalid JWT for path: {}", request.getPath());
                    return onError(exchange, "JWT token is not valid",
                            HttpStatus.UNAUTHORIZED);
                }

                Claims claims  = extractClaims(jwt);
                Long userId    = claims.get("userId", Long.class);
                String username = claims.getSubject();
                String role    = claims.get("role", String.class); // extract role

                if (userId == null || username == null) {
                    log.warn("JWT missing userId or username");
                    return onError(exchange, "Invalid token claims",
                            HttpStatus.UNAUTHORIZED);
                }

                // normalize role — default USER if missing
                String resolvedRole = (role != null && !role.isBlank())
                        ? role.toUpperCase()
                        : "USER";

                log.info("JWT valid — userId: {}, username: {}, role: {}",
                        userId, username, resolvedRole);

                // forward all headers to downstream services
                ServerHttpRequest modifiedRequest = request.mutate()
                        .header("X-User-Id",   userId.toString())
                        .header("X-User-Name", username)
                        .header("X-User-Role", resolvedRole) // role forwarded
                        .build();

                return chain.filter(
                        exchange.mutate().request(modifiedRequest).build());

            } catch (Exception e) {
                log.error("Gateway Filter Exception: {}", e.getMessage(), e);
                return onError(exchange, "Authentication error",
                        HttpStatus.INTERNAL_SERVER_ERROR);
            }
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange,
                               String err,
                               HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        response.getHeaders().add("Content-Type", "application/json");

        String json = String.format(
                "{\"success\":false,\"code\":\"%s\",\"message\":\"%s\",\"timestamp\":\"%s\"}",
                httpStatus.name(), err, LocalDateTime.now()
        );

        DataBufferFactory factory = response.bufferFactory();
        DataBuffer buffer = factory.wrap(json.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    private boolean isJwtValid(String jwt) {
        try {
            String secret = env.getProperty("jwt.secret");
            if (secret == null || secret.isBlank()) {
                log.error("JWT secret is null or empty");
                return false;
            }
            SecretKey key = Keys.hmacShaKeyFor(
                    secret.getBytes(StandardCharsets.UTF_8));
            Jwts.parser().verifyWith(key).build().parseSignedClaims(jwt);
            return true;
        } catch (Exception ex) {
            log.warn("JWT validation failed: {}", ex.getMessage());
            return false;
        }
    }

    private Claims extractClaims(String jwt) {
        String secret = env.getProperty("jwt.secret");
        SecretKey key = Keys.hmacShaKeyFor(
                secret.getBytes(StandardCharsets.UTF_8));
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
    }
}