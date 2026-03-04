package com.fund.transfer.api.gateway.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class SecurityResponseFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange,
                             org.springframework.cloud.gateway.filter.GatewayFilterChain chain) {

        ServerHttpResponse decoratedResponse = new ServerHttpResponseDecorator(exchange.getResponse()) {
            @Override
            public Mono<Void> writeWith(org.reactivestreams.Publisher<? extends org.springframework.core.io.buffer.DataBuffer> body) {
                addSecurityHeaders();
                return super.writeWith(body);
            }

            @Override
            public Mono<Void> writeAndFlushWith(org.reactivestreams.Publisher<? extends org.reactivestreams.Publisher<? extends org.springframework.core.io.buffer.DataBuffer>> body) {
                addSecurityHeaders();
                return super.writeAndFlushWith(body);
            }

            private void addSecurityHeaders() {
                org.springframework.http.HttpHeaders headers = getHeaders();
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
        };

        return chain.filter(exchange.mutate().response(decoratedResponse).build());
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}