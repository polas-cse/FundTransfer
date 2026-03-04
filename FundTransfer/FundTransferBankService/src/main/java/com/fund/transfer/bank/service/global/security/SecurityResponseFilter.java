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
        return chain.filter(exchange)
                .doFinally(signal ->  
                        exchange.getResponse().getHeaders().addAll(buildSecurityHeaders())
                );
    }

    private HttpHeaders buildSecurityHeaders() {
        HttpHeaders headers = new HttpHeaders();

        // Prevent MIME type sniffing
        headers.add("X-Content-Type-Options", "nosniff");

        // Prevent clickjacking
        headers.add("X-Frame-Options", "DENY");

        // Enable browser XSS filter
        headers.add("X-XSS-Protection", "1; mode=block");

        // Control what data can be loaded
        headers.add("Content-Security-Policy",
                "default-src 'self'; script-src 'self'; object-src 'none'");

        // Prevent caching of sensitive responses
        headers.add("Cache-Control", "no-store, no-cache, must-revalidate");
        headers.add("Pragma", "no-cache");

        // Force HTTPS
        headers.add("Strict-Transport-Security",
                "max-age=31536000; includeSubDomains; preload");

        // Control referrer info sent to other sites
        headers.add("Referrer-Policy", "strict-origin-when-cross-origin");

        // Restrict browser features
        headers.add("Permissions-Policy",
                "geolocation=(), microphone=(), camera=()");

        return headers;
    }
}