package com.fund.transfer.api.gateway.security;

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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

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

                System.out.println("🔍 Gateway Filter - Processing request: " + request.getPath());

                if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    System.err.println("❌ No authorization header");
                    return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
                }

                String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                System.out.println("📝 Authorization header found");

                if (!authorizationHeader.startsWith("Bearer ")) {
                    System.err.println("❌ Invalid authorization header format");
                    return onError(exchange, "Invalid authorization header format", HttpStatus.UNAUTHORIZED);
                }

                String jwt = authorizationHeader.replace("Bearer ", "");
                System.out.println("🔑 JWT Token extracted (first 20 chars): " + jwt.substring(0, Math.min(20, jwt.length())));

                if (!isJwtValid(jwt)) {
                    System.err.println("❌ JWT token is not valid");
                    return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
                }

                Claims claims = extractClaims(jwt);
                Long userId = claims.get("userId", Long.class);
                String username = claims.getSubject();

                System.out.println("✅ JWT Valid - UserId: " + userId + ", Username: " + username);

                ServerHttpRequest modifiedRequest = request.mutate()
                        .header("X-User-Id", userId.toString())
                        .header("X-User-Name", username)
                        .build();

                System.out.println("✅ Headers added - Forwarding to service");

                return chain.filter(exchange.mutate().request(modifiedRequest).build());

            } catch (Exception e) {
                System.err.println("❌ Gateway Filter Exception: " + e.getClass().getName());
                System.err.println("❌ Error Message: " + e.getMessage());
                e.printStackTrace();
                return onError(exchange, "Authentication error: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
            }
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        System.err.println("⚠️ Sending error response: " + err + " (Status: " + httpStatus + ")");
        DataBufferFactory bufferFactory = response.bufferFactory();
        String jsonError = String.format("{\"error\":\"%s\",\"status\":%d,\"timestamp\":\"%s\"}", err, httpStatus.value(), java.time.LocalDateTime.now());
        DataBuffer dataBuffer = bufferFactory.wrap(jsonError.getBytes(StandardCharsets.UTF_8));
        response.getHeaders().add("Content-Type", "application/json");

        return response.writeWith(Mono.just(dataBuffer));
    }

    private boolean isJwtValid(String jwt) {
        try {
            String tokenSecret = env.getProperty("jwt.secret");

            if (tokenSecret == null || tokenSecret.isEmpty()) {
                System.err.println("❌ JWT secret is null or empty!");
                return false;
            }

            System.out.println("🔐 JWT Secret length: " + tokenSecret.length());

            SecretKey signingKey = Keys.hmacShaKeyFor(tokenSecret.getBytes(StandardCharsets.UTF_8));

            Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(jwt);

            System.out.println("✅ JWT validation successful");
            return true;
        } catch (Exception ex) {
            System.err.println("❌ JWT validation failed: " + ex.getClass().getName() + " - " + ex.getMessage());
            return false;
        }
    }

    private Claims extractClaims(String jwt) {
        String tokenSecret = env.getProperty("jwt.secret");
        SecretKey signingKey = Keys.hmacShaKeyFor(tokenSecret.getBytes(StandardCharsets.UTF_8));

        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
    }
}