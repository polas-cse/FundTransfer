package com.fund.transfer.api.gateway.cyber.model;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;

@Builder
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Table("security_audit_log")
public class SecurityLog {

    @Id
    private Long id;

    // ── Request Info ─────────────────────────────────────────────────
    @Column("request_id")     private String requestId;
    @Column("ip_address")     private String ipAddress;
    @Column("user_agent")     private String userAgent;
    @Column("request_path")   private String requestPath;
    @Column("request_method") private String requestMethod;
    @Column("query_string")   private String queryString;
    @Column("request_body")   private String requestBody;
    @Column("referer")        private String referer;
    @Column("origin")         private String origin;
    @Column("content_length") private Long contentLength;
    @Column("protocol")       private String protocol;

    // ── User Info ─────────────────────────────────────────────────────
    @Column("user_id")    private String userId;
    @Column("username")   private String username;
    @Column("user_role")  private String userRole;
    @Column("session_id") private String sessionId;

    // ── Threat Info ───────────────────────────────────────────────────
    @Column("threat_type")      private String threatType;
    @Column("severity")         private String severity;
    @Column("status")           private String status;
    @Column("field_name")       private String fieldName;
    @Column("suspicious_value") private String suspiciousValue;
    @Column("message")          private String message;
    @Column("rule_triggered")   private String ruleTriggered;
    @Column("blocked")          private Boolean blocked;
    @Column("block_reason")     private String blockReason;

    // ── Meta ──────────────────────────────────────────────────────────
    @Column("service_id")       private String serviceId;
    @Column("response_time_ms") private Long responseTimeMs;
    @Column("detected_at")      private LocalDateTime detectedAt;
    @Column("created_at")       private LocalDateTime createdAt;
}