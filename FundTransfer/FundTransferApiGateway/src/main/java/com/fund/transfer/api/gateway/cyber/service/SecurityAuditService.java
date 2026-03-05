package com.fund.transfer.api.gateway.cyber.service;

import com.fund.transfer.api.gateway.cyber.event.SecurityAuditEvent;
import com.fund.transfer.api.gateway.cyber.model.SecurityLog;
import com.fund.transfer.api.gateway.cyber.repository.SecurityLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class SecurityAuditService {

    private final SecurityLogRepository repository;

    @Value("${spring.application.name:api-gateway}")
    private String serviceName;

    // async save — never blocks gateway
    public void recordAsync(SecurityAuditEvent event) {
        Mono.fromCallable(() -> buildLog(event))
                .flatMap(repository::save)
                .subscribeOn(Schedulers.boundedElastic())
                .doOnError(ex ->
                        log.error("Failed to save security audit log: {}",
                                ex.getMessage()))
                .subscribe();
    }

    // sync save — when you need to wait (rare)
    public Mono<SecurityLog> record(SecurityAuditEvent event) {
        return repository.save(buildLog(event));
    }

    private SecurityLog buildLog(SecurityAuditEvent event) {
        // console log based on severity
        logToConsole(event);

        return SecurityLog.builder()
                .requestId(event.getRequestId())
                .ipAddress(event.getIpAddress())
                .userAgent(event.getUserAgent())
                .requestPath(event.getRequestPath())
                .requestMethod(event.getRequestMethod())
                .queryString(event.getQueryString())
                .requestBody(event.getRequestBody())
                .referer(event.getReferer())
                .origin(event.getOrigin())
                .contentLength(event.getContentLength())
                .protocol(event.getProtocol())
                .userId(event.getUserId())
                .username(event.getUsername())
                .userRole(event.getUserRole())
                .sessionId(event.getSessionId())
                .threatType(event.getThreatType() != null
                        ? event.getThreatType().name() : "UNKNOWN")
                .severity(event.getSeverity() != null
                        ? event.getSeverity().name() : "LOW")
                .status(event.getStatus() != null
                        ? event.getStatus().name() : "DETECTED")
                .fieldName(event.getFieldName())
                .suspiciousValue(event.getSuspiciousValue())
                .message(event.getMessage())
                .ruleTriggered(event.getRuleTriggered())
                .blocked(event.isBlocked())
                .blockReason(event.getBlockReason())
                .serviceId(serviceName)
                .responseTimeMs(event.getResponseTimeMs())
                .detectedAt(event.getDetectedAt() != null
                        ? event.getDetectedAt() : LocalDateTime.now())
                .createdAt(LocalDateTime.now())
                .build();
    }

    private void logToConsole(SecurityAuditEvent event) {
        String prefix = "[SECURITY-" + event.getSeverity() + "]";
        String blocked = event.isBlocked() ? "🚫 BLOCKED" : "⚠️ DETECTED";

        switch (event.getSeverity()) {
            case CRITICAL -> log.error(
                    "{} {} {} | ip={} | user={} | path={} | msg={}",
                    prefix, blocked, event.getThreatType(),
                    event.getIpAddress(), event.getUsername(),
                    event.getRequestPath(), event.getMessage());
            case HIGH -> log.error(
                    "{} {} | ip={} | user={} | path={} | msg={}",
                    prefix, event.getThreatType(),
                    event.getIpAddress(), event.getUsername(),
                    event.getRequestPath(), event.getMessage());
            case MEDIUM -> log.warn(
                    "{} {} | ip={} | path={} | msg={}",
                    prefix, event.getThreatType(),
                    event.getIpAddress(),
                    event.getRequestPath(), event.getMessage());
            default -> log.info(
                    "{} {} | ip={} | msg={}",
                    prefix, event.getThreatType(),
                    event.getIpAddress(), event.getMessage());
        }
    }

    public Flux<SecurityLog> getLogs(String severity, String threatType,
                                     String ip, String username,
                                     Boolean blocked, int limit) {
        return repository.findByFilters(severity, threatType,
                ip, username, blocked, limit);
    }

    public Mono<Long> getCriticalCount(int hours) {
        return repository.countCriticalSince(
                LocalDateTime.now().minusHours(hours));
    }
}
