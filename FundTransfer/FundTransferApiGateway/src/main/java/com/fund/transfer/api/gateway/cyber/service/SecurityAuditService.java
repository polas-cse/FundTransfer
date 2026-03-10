package com.fund.transfer.api.gateway.cyber.service;

import com.fund.transfer.api.gateway.cyber.event.SecurityAuditEvent;
import com.fund.transfer.api.gateway.cyber.repository.SecurityLogRepository;
import com.fund.transfer.api.gateway.cyber.model.SecurityLog;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@Slf4j
@Service
@RequiredArgsConstructor
public class SecurityAuditService {

    private final SecurityLogRepository repository;

    // ══════════════════════════════════════════════════════════════════
    // ANSI Colors
    // ══════════════════════════════════════════════════════════════════

    private static final String RESET   = "\u001B[0m";
    private static final String BOLD    = "\u001B[1m";

    // text colors
    private static final String RED     = "\u001B[31m";
    private static final String YELLOW  = "\u001B[33m";
    private static final String CYAN    = "\u001B[36m";
    private static final String WHITE   = "\u001B[37m";
    private static final String MAGENTA = "\u001B[35m";
    private static final String GREEN   = "\u001B[32m";

    // background colors
    private static final String BG_RED     = "\u001B[41m";
    private static final String BG_YELLOW  = "\u001B[43m";
    private static final String BG_MAGENTA = "\u001B[45m";
    private static final String BG_CYAN    = "\u001B[46m";

    // ══════════════════════════════════════════════════════════════════
    // Severity Icons
    // ══════════════════════════════════════════════════════════════════

    private static final String ICON_CRITICAL = "🔴";
    private static final String ICON_HIGH     = "🟠";
    private static final String ICON_MEDIUM   = "🟡";
    private static final String ICON_LOW      = "🔵";
    private static final String ICON_INFO     = "⚪";
    private static final String ICON_BLOCKED  = "🚫";
    private static final String ICON_DETECTED = "⚠️ ";

    // ══════════════════════════════════════════════════════════════════
    // Record Async
    // ══════════════════════════════════════════════════════════════════

    public void recordAsync(SecurityAuditEvent event) {
        Mono.fromCallable(() -> toEntity(event))
                .flatMap(repository::save)
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(saved -> logToConsole(event))
                .doOnError(err -> log.error(
                        "{}{}[AUDIT-ERROR]{} Failed to save security event: {}",
                        BOLD, RED, RESET, err.getMessage()))
                .subscribe();
    }

    // ══════════════════════════════════════════════════════════════════
    // Beautiful Console Log
    // ══════════════════════════════════════════════════════════════════

    private void logToConsole(SecurityAuditEvent event) {

        String severityColor = getSeverityColor(event.getSeverity());
        String icon          = getIcon(event);
        String statusIcon    = event.isBlocked() ? "🚫 BLOCKED" : "⚠️  DETECTED";

        // ── separator line ────────────────────────────────────────────────
        String topLine    = BOLD + severityColor
                + "  ╔════════════════════════════════════════════════════════════════╗"
                + RESET;
        String bottomLine = BOLD + severityColor
                + "  ╚════════════════════════════════════════════════════════════════╝"
                + RESET;
        String divider    = severityColor
                + "  ║════════════════════════════════════════════════════════════════║"
                + RESET;

        String msg = "\n" + topLine + "\n"

                // ── title ─────────────────────────────────────────────────────
                + severityColor + "  ║  " + RESET
                + BOLD + severityColor + icon + "  "
                + String.format("%-30s", event.getThreatType())
                + RESET
                + BOLD + severityColor
                + "  [" + event.getSeverity() + "]"
                + "  " + statusIcon
                + RESET + "\n"

                + divider + "\n"

                // ── request ───────────────────────────────────────────────────
                + severityColor + "  ║  " + RESET
                + BOLD + CYAN    + "📡 REQUEST" + RESET + "\n"

                + severityColor + "  ║  " + RESET
                + CYAN           + "     Method   : " + RESET
                + BOLD + WHITE   + nvl(event.getRequestMethod()) + RESET + "\n"

                + severityColor + "  ║  " + RESET
                + CYAN           + "     Path     : " + RESET
                + BOLD + WHITE   + nvl(event.getRequestPath()) + RESET + "\n"

                + severityColor + "  ║  " + RESET
                + CYAN           + "     IP       : " + RESET
                + BOLD + WHITE   + nvl(event.getIpAddress()) + RESET + "\n"

                + severityColor + "  ║  " + RESET
                + CYAN           + "     Protocol : " + RESET
                + BOLD + WHITE   + nvl(event.getProtocol()) + RESET + "\n"

                + (event.getQueryString() != null
                ? severityColor + "  ║  " + RESET
                + CYAN         + "     Query    : " + RESET
                + BOLD + WHITE + event.getQueryString() + RESET + "\n"
                : "")

                + divider + "\n"

                // ── user ──────────────────────────────────────────────────────
                + severityColor + "  ║  " + RESET
                + BOLD + MAGENTA + "👤 USER" + RESET + "\n"

                + severityColor + "  ║  " + RESET
                + MAGENTA        + "     Username : " + RESET
                + BOLD + WHITE   + nvl(event.getUsername()) + RESET + "\n"

                + severityColor + "  ║  " + RESET
                + MAGENTA        + "     User ID  : " + RESET
                + BOLD + WHITE   + nvl(event.getUserId()) + RESET + "\n"

                + severityColor + "  ║  " + RESET
                + MAGENTA        + "     Role     : " + RESET
                + BOLD + WHITE   + nvl(event.getUserRole()) + RESET + "\n"

                + severityColor + "  ║  " + RESET
                + MAGENTA        + "     Agent    : " + RESET
                + BOLD + WHITE   + nvl(event.getUserAgent()) + RESET + "\n"

                + divider + "\n"

                // ── threat ────────────────────────────────────────────────────
                + severityColor + "  ║  " + RESET
                + BOLD + severityColor + "🛡️  THREAT" + RESET + "\n"

                + severityColor + "  ║  " + RESET
                + severityColor  + "     Field    : " + RESET
                + BOLD + severityColor + nvl(event.getFieldName()) + RESET + "\n"

                + severityColor + "  ║  " + RESET
                + severityColor  + "     Payload  : " + RESET
                + BOLD + severityColor + nvl(event.getSuspiciousValue()) + RESET + "\n"

                + severityColor + "  ║  " + RESET
                + severityColor  + "     Message  : " + RESET
                + BOLD + WHITE   + nvl(event.getMessage()) + RESET + "\n"

                + (event.isBlocked()
                ? severityColor + "  ║  " + RESET
                + severityColor + "     Reason   : " + RESET
                + BOLD + RED   + nvl(event.getBlockReason()) + RESET + "\n"
                : "")

                + (event.getResponseTimeMs() != null
                ? severityColor + "  ║  " + RESET
                + YELLOW        + "     RespTime : " + RESET
                + BOLD + YELLOW + event.getResponseTimeMs() + "ms" + RESET + "\n"
                : "")

                + divider + "\n"

                // ── meta ──────────────────────────────────────────────────────
                + severityColor + "  ║  " + RESET
                + BOLD + GREEN  + "🕐 META" + RESET + "\n"

                + severityColor + "  ║  " + RESET
                + GREEN          + "     Time     : " + RESET
                + BOLD + WHITE   + nvl(String.valueOf(event.getDetectedAt())) + RESET + "\n"

                + severityColor + "  ║  " + RESET
                + GREEN          + "     Service  : " + RESET
                + BOLD + WHITE   + nvl(event.getServiceId()) + RESET + "\n"

                + bottomLine + "\n";

        log.warn(msg);
    }

    // ══════════════════════════════════════════════════════════════════
    // Color Helpers
    // ══════════════════════════════════════════════════════════════════

    private String getSeverityColor(SecurityAuditEvent.Severity severity) {
        if (severity == null) return WHITE;
        return switch (severity) {
            case CRITICAL -> RED;
            case HIGH     -> YELLOW;
            case MEDIUM   -> MAGENTA;
            case LOW      -> CYAN;
            case INFO     -> WHITE;
        };
    }

    private String getSeverityBg(SecurityAuditEvent.Severity severity) {
        if (severity == null) return "";
        return switch (severity) {
            case CRITICAL -> BG_RED;
            case HIGH     -> BG_YELLOW;
            case MEDIUM   -> BG_MAGENTA;
            case LOW      -> BG_CYAN;
            case INFO     -> "";
        };
    }

    private String getIcon(SecurityAuditEvent event) {
        if (event.isBlocked()) return ICON_BLOCKED;
        if (event.getSeverity() == null) return ICON_INFO;
        return switch (event.getSeverity()) {
            case CRITICAL -> ICON_CRITICAL;
            case HIGH     -> ICON_HIGH;
            case MEDIUM   -> ICON_MEDIUM;
            case LOW      -> ICON_LOW;
            case INFO     -> ICON_INFO;
        };
    }

    private String nvl(String value) {
        return value != null ? value : "-";
    }

    // ══════════════════════════════════════════════════════════════════
    // Entity Mapper
    // ══════════════════════════════════════════════════════════════════

    private SecurityLog toEntity(SecurityAuditEvent event) {
        return SecurityLog.builder()
                .ipAddress(event.getIpAddress())
                .userAgent(event.getUserAgent())
                .requestPath(event.getRequestPath())
                .requestMethod(event.getRequestMethod())
                .queryString(event.getQueryString())
                .referer(event.getReferer())
                .origin(event.getOrigin())
                .contentLength(event.getContentLength())
                .protocol(event.getProtocol())
                .userId(event.getUserId())
                .username(event.getUsername())
                .userRole(event.getUserRole())
                .threatType(event.getThreatType() != null
                        ? event.getThreatType().name() : null)
                .severity(event.getSeverity() != null
                        ? event.getSeverity().name() : null)
                .status(event.getStatus() != null
                        ? event.getStatus().name() : null)
                .fieldName(event.getFieldName())
                .suspiciousValue(event.getSuspiciousValue())
                .message(event.getMessage())
                .blocked(event.isBlocked())
                .blockReason(event.getBlockReason())
                .serviceId(event.getServiceId())
                .responseTimeMs(event.getResponseTimeMs())
                .detectedAt(event.getDetectedAt())
                .build();
    }
}