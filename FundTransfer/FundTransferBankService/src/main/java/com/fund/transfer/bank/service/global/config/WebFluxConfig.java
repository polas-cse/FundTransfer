package com.fund.transfer.bank.service.global.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.reactive.config.ResourceHandlerRegistry;

/**
 * WebFlux Configuration to prevent static resource handler from intercepting controller routes.
 * This ensures that controller endpoints take precedence over static resource handling.
 */
@Configuration
public class WebFluxConfig implements WebFluxConfigurer {

    /**
     * Override resource handling to disable default static resource locations.
     * This prevents the static resource handler from intercepting API controller requests.
     */
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // Don't add any resource handlers - this prevents static resources from being served
        // and ensures all requests are routed to controllers if they match a @RequestMapping
    }
}
