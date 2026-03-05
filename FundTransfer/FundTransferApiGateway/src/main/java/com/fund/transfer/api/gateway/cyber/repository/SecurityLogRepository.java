package com.fund.transfer.api.gateway.cyber.repository;

import com.fund.transfer.api.gateway.cyber.model.SecurityLog;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

public interface SecurityLogRepository
        extends ReactiveCrudRepository<SecurityLog, Long> {

    @Query("""
        SELECT * FROM security_audit_log
        WHERE (:severity   IS NULL OR severity    = :severity)
        AND   (:threatType IS NULL OR threat_type = :threatType)
        AND   (:ip         IS NULL OR ip_address  = :ip)
        AND   (:username   IS NULL OR username    = :username)
        AND   (:blocked    IS NULL OR blocked     = :blocked)
        ORDER BY detected_at DESC
        LIMIT :limitVal
        """)
    Flux<SecurityLog> findByFilters(String severity, String threatType,
                                    String ip, String username,
                                    Boolean blocked, int limitVal);

    @Query("""
        SELECT * FROM security_audit_log
        WHERE ip_address = :ip
        AND   detected_at >= :since
        ORDER BY detected_at DESC
        """)
    Flux<SecurityLog> findByIpSince(String ip, LocalDateTime since);

    @Query("""
        SELECT COUNT(*) FROM security_audit_log
        WHERE ip_address = :ip
        AND   detected_at >= :since
        """)
    Mono<Long> countByIpSince(String ip, LocalDateTime since);

    @Query("""
        SELECT COUNT(*) FROM security_audit_log
        WHERE severity = 'CRITICAL'
        AND   detected_at >= :since
        """)
    Mono<Long> countCriticalSince(LocalDateTime since);

    Flux<SecurityLog> findByBlockedTrueOrderByDetectedAtDesc();

    @Query("""
        SELECT threat_type, COUNT(*) as cnt
        FROM security_audit_log
        WHERE detected_at >= :since
        GROUP BY threat_type
        ORDER BY cnt DESC
        LIMIT 10
        """)
    Flux<Object> topThreatsSince(LocalDateTime since);

    @Query("""
        SELECT ip_address, COUNT(*) as cnt
        FROM security_audit_log
        WHERE detected_at >= :since
        GROUP BY ip_address
        ORDER BY cnt DESC
        LIMIT 10
        """)
    Flux<Object> topAttackerIpsSince(LocalDateTime since);
}