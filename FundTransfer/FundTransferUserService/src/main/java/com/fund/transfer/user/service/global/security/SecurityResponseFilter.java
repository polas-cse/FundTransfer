package com.fund.transfer.user.service.global.security;

import lombok.extern.slf4j.Slf4j;
import org.reactivestreams.Publisher;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class SecurityResponseFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpResponse decoratedResponse =
                new SecurityHttpResponseDecorator(exchange.getResponse());

        return chain.filter(exchange.mutate().response(decoratedResponse).build());
    }

    // named static inner class — no more $1 anonymous class problem
    static class SecurityHttpResponseDecorator extends ServerHttpResponseDecorator {

        public SecurityHttpResponseDecorator(ServerHttpResponse delegate) {
            super(delegate);
        }

        @Override
        public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
            addSecurityHeaders();
            return super.writeWith(body);
        }

        @Override
        public Mono<Void> writeAndFlushWith(
                Publisher<? extends Publisher<? extends DataBuffer>> body) {
            addSecurityHeaders();
            return super.writeAndFlushWith(body);
        }

        private void addSecurityHeaders() {
            HttpHeaders headers = getHeaders();
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
}