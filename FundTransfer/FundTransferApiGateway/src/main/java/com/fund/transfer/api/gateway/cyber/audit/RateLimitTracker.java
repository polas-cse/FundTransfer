package com.fund.transfer.api.gateway.cyber.audit;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
@Component
@EnableScheduling
public class RateLimitTracker {

    @Value("${security.rate-limit.max-requests-per-ip:100}")
    private int maxRequestsPerIp;

    @Value("${security.rate-limit.max-requests-per-user:60}")
    private int maxRequestsPerUser;

    @Value("${security.rate-limit.max-failed-login:5}")
    private int maxFailedLogin;

    // ── Counters ──────────────────────────────────────────────────────
    private final ConcurrentHashMap<String, AtomicInteger> ipCounter
            = new ConcurrentHashMap<>();

    private final ConcurrentHashMap<String, AtomicInteger> userCounter
            = new ConcurrentHashMap<>();

    private final ConcurrentHashMap<String, AtomicInteger> failedLoginCounter
            = new ConcurrentHashMap<>();

    // ── IP Rate Limit ─────────────────────────────────────────────────

    /**
     * Increment IP counter and check if limit exceeded.
     * Returns true if rate limited.
     */
    public boolean isIpRateLimited(String ip) {
        if (ip == null || ip.isBlank()) return false;
        int count = ipCounter
                .computeIfAbsent(ip, k -> new AtomicInteger(0))
                .incrementAndGet();
        if (count > maxRequestsPerIp) {
            log.warn("[RATE-LIMIT] IP: {} exceeded limit — {} requests/min",
                    ip, count);
            return true;
        }
        return false;
    }

    public int getIpCount(String ip) {
        AtomicInteger counter = ipCounter.get(ip);
        return counter != null ? counter.get() : 0;
    }

    // ── User Rate Limit ───────────────────────────────────────────────

    /**
     * Increment user counter and check if limit exceeded.
     * Returns true if rate limited.
     */
    public boolean isUserRateLimited(String username) {
        if (username == null || username.isBlank()) return false;
        int count = userCounter
                .computeIfAbsent(username, k -> new AtomicInteger(0))
                .incrementAndGet();
        if (count > maxRequestsPerUser) {
            log.warn("[RATE-LIMIT] User: {} exceeded limit — {} requests/min",
                    username, count);
            return true;
        }
        return false;
    }

    public int getUserCount(String username) {
        AtomicInteger counter = userCounter.get(username);
        return counter != null ? counter.get() : 0;
    }

    // ── Failed Login Tracking ─────────────────────────────────────────

    /**
     * Increment failed login counter for IP.
     * Returns true if brute force threshold exceeded.
     */
    public boolean recordFailedLogin(String ip, String username) {
        boolean ipBlocked = false;
        boolean userBlocked = false;

        if (ip != null) {
            int ipCount = failedLoginCounter
                    .computeIfAbsent("ip:" + ip, k -> new AtomicInteger(0))
                    .incrementAndGet();
            if (ipCount >= maxFailedLogin) {
                log.error("[BRUTE-FORCE] IP: {} — {} failed login attempts",
                        ip, ipCount);
                ipBlocked = true;
            }
        }

        if (username != null) {
            int userCount = failedLoginCounter
                    .computeIfAbsent("user:" + username, k -> new AtomicInteger(0))
                    .incrementAndGet();
            if (userCount >= maxFailedLogin) {
                log.error("[BRUTE-FORCE] User: {} — {} failed login attempts",
                        username, userCount);
                userBlocked = true;
            }
        }

        return ipBlocked || userBlocked;
    }

    public int getFailedLoginCount(String ip) {
        AtomicInteger counter = failedLoginCounter.get("ip:" + ip);
        return counter != null ? counter.get() : 0;
    }

    public int getFailedLoginCountByUser(String username) {
        AtomicInteger counter = failedLoginCounter.get("user:" + username);
        return counter != null ? counter.get() : 0;
    }

    /**
     * Call this on successful login — reset counters
     */
    public void resetFailedLogin(String ip, String username) {
        if (ip != null) {
            failedLoginCounter.remove("ip:" + ip);
            log.debug("[RATE-LIMIT] Reset failed login counter for IP: {}", ip);
        }
        if (username != null) {
            failedLoginCounter.remove("user:" + username);
            log.debug("[RATE-LIMIT] Reset failed login counter for user: {}", username);
        }
    }

    // ── DDoS Detection ────────────────────────────────────────────────

    /**
     * Check if IP is making suspiciously high number of requests.
     * Higher threshold than normal rate limit — indicates DDoS.
     */
    public boolean isDdosSuspected(String ip) {
        if (ip == null) return false;
        int count = getIpCount(ip);
        boolean suspected = count > (maxRequestsPerIp * 3); // 3x normal limit
        if (suspected) {
            log.error("[DDOS-SUSPECTED] IP: {} — {} requests/min", ip, count);
        }
        return suspected;
    }

    // ── Scheduled Reset ───────────────────────────────────────────────

    /**
     * Reset request counters every minute.
     * Failed login counters persist until successful login.
     */
    @Scheduled(fixedRate = 60_000) // every 60 seconds
    public void resetRequestCounters() {
        int ipCount   = ipCounter.size();
        int userCount = userCounter.size();

        ipCounter.clear();
        userCounter.clear();

        log.debug("[RATE-LIMIT] Counters reset — cleared {} IPs, {} users",
                ipCount, userCount);
    }

    /**
     * Reset failed login counters every 15 minutes.
     * Gives locked users a chance to retry after cooldown.
     */
    @Scheduled(fixedRate = 900_000) // every 15 minutes
    public void resetFailedLoginCounters() {
        int count = failedLoginCounter.size();
        failedLoginCounter.clear();
        log.debug("[RATE-LIMIT] Failed login counters reset — cleared {}",
                count);
    }

    // ── Stats ─────────────────────────────────────────────────────────

    public int getTotalTrackedIps() {
        return ipCounter.size();
    }

    public int getTotalTrackedUsers() {
        return userCounter.size();
    }

    public int getTotalFailedLoginEntries() {
        return failedLoginCounter.size();
    }
}