package com.fund.transfer.bank.service.global.security;

import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
public class SecurityResponseFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        addSecurityHeaders(exchange.getResponse().getHeaders());
        return chain.filter(exchange);
    }

    private void addSecurityHeaders(HttpHeaders headers) {
        if (!headers.containsKey("X-Content-Type-Options")) {
            headers.add("X-Content-Type-Options", "nosniff");
            headers.add("X-Frame-Options", "DENY");
            headers.add("X-XSS-Protection", "1; mode=block");
            headers.add("Content-Security-Policy",
                    "default-src 'self'; script-src 'self'; object-src 'none'");
            headers.add("Cache-Control", "no-store, no-cache, must-revalidate");
            headers.add("Pragma", "no-cache");
            headers.add("Strict-Transport-Security",
                    "max-age=31536000; includeSubDomains; preload");
            headers.add("Referrer-Policy", "strict-origin-when-cross-origin");
            headers.add("Permissions-Policy",
                    "geolocation=(), microphone=(), camera=()");
        }
    }
}
