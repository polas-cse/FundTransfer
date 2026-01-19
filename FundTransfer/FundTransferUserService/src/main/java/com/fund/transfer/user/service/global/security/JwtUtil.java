package com.fund.transfer.user.service.global.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateToken(String username, Long userId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);

        return Jwts.builder()
                .claims(claims)
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey())
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    public Mono<Long> getUserId() {
        return ReactiveSecurityContextHolder.getContext()
                .doOnNext(ctx -> System.out.println("🔍 Security Context: " + ctx))
                .map(ctx -> ctx.getAuthentication())
                .flatMap(auth -> {

                    Object credentials = auth.getCredentials();
                    if (credentials instanceof String) {
                        return Mono.just((String) credentials);
                    }

                    Object details = auth.getDetails();
                    if (details instanceof String) {
                        return Mono.just((String) details);
                    }

                    Object principal = auth.getPrincipal();
                    if (principal instanceof String) {
                        return Mono.just((String) principal);
                    }

                    return Mono.empty();
                })
                .map(token -> {
                    Long userId = extractUserId(token);
                    System.out.println("Extracted userId: " + userId);
                    return userId;
                })
                .doOnError(e -> System.err.println("Error extracting userId: " + e.getMessage()))
                .switchIfEmpty(Mono.defer(() -> {
                    System.err.println("No userId found, using default");
                    return Mono.just(1L);
                }));
    }

    public Long extractUserId(String token) {
        return extractClaims(token).get("userId", Long.class);
    }

    public boolean isTokenValid(String token) {
        try {
            extractClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    private Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

}