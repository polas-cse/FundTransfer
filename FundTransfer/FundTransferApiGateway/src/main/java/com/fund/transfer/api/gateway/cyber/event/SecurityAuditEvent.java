package com.fund.transfer.api.gateway.cyber.event;

import lombok.*;

import java.time.LocalDateTime;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class SecurityAuditEvent {

    public enum ThreatType {
        // ── Input Attacks ─────────────────────────────────────────────
        XSS_ATTEMPT,
        SQL_INJECTION,
        NOSQL_INJECTION,
        PATH_TRAVERSAL,
        COMMAND_INJECTION,
        LDAP_INJECTION,
        XML_INJECTION,
        JSON_INJECTION,
        HTML_INJECTION,
        TEMPLATE_INJECTION,
        HEADER_INJECTION,
        LOG4J_INJECTION,
        DESERIALIZATION_ATTACK,

        // ── Auth Attacks ──────────────────────────────────────────────
        BRUTE_FORCE,
        CREDENTIAL_STUFFING,
        INVALID_JWT,
        EXPIRED_JWT,
        TAMPERED_JWT,
        UNAUTHORIZED_ACCESS,
        PRIVILEGE_ESCALATION,

        // ── Traffic Attacks ───────────────────────────────────────────
        RATE_LIMIT_EXCEEDED,
        DDOS_SUSPECTED,
        LARGE_PAYLOAD,
        SLOW_LORIS,

        // ── Reconnaissance ────────────────────────────────────────────
        SCANNER_DETECTED,
        SUSPICIOUS_USER_AGENT,
        PATH_ENUMERATION,
        PORT_SCANNING,

        // ── Protocol Attacks ──────────────────────────────────────────
        HTTP_METHOD_TAMPERING,
        HTTP_SMUGGLING,
        HOST_HEADER_INJECTION,
        SUSPICIOUS_HEADER,
        MISSING_HEADERS,
        CORS_VIOLATION,

        // ── Other ─────────────────────────────────────────────────────
        REPEATED_VALIDATION_FAIL,
        SUSPICIOUS_PATTERN,
        OPEN_REDIRECT,
        UNKNOWN
    }

    public enum Severity {
        INFO, LOW, MEDIUM, HIGH, CRITICAL
    }

    public enum AttackStatus {
        DETECTED,   // detected but request allowed through
        BLOCKED,    // request was blocked — 403 returned
        MONITORED   // flagged for monitoring
    }

    // ── Request Info ─────────────────────────────────────────────────
    private String requestId;
    private String ipAddress;
    private String userAgent;
    private String requestPath;
    private String requestMethod;
    private String queryString;
    private String requestBody;
    private String referer;
    private String origin;
    private Long   contentLength;
    private String protocol;

    // ── User Info ─────────────────────────────────────────────────────
    private String userId;
    private String username;
    private String userRole;
    private String sessionId;

    // ── Threat Info ───────────────────────────────────────────────────
    private ThreatType   threatType;
    private Severity     severity;
    private AttackStatus status;
    private String       fieldName;
    private String       suspiciousValue;
    private String       message;
    private String       ruleTriggered;
    private boolean      blocked;
    private String       blockReason;

    // ── Meta ──────────────────────────────────────────────────────────
    private String        serviceId;
    private Long          responseTimeMs;
    private LocalDateTime detectedAt;
}