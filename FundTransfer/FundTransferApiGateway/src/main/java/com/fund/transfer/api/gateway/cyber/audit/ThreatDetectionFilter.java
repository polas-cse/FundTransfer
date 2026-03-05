package com.fund.transfer.api.gateway.cyber.audit;

import com.fund.transfer.api.gateway.cyber.event.SecurityAuditEvent;
import com.fund.transfer.api.gateway.cyber.service.SecurityAuditService;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Component
@RequiredArgsConstructor
public class ThreatDetectionFilter implements GlobalFilter, Ordered {

    private final SecurityAuditService auditService;
    private final RateLimitTracker     rateLimitTracker;

    @Value("${spring.application.name:api-gateway}")
    private String serviceName;

    // ══════════════════════════════════════════════════════════════════
    // HTTP Methods
    // ══════════════════════════════════════════════════════════════════

    private static final Set<String> ALLOWED_METHODS = Set.of(
            "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
    );

    private static final Map<String, String> BLOCKED_METHODS = Map.ofEntries(
            Map.entry("TRACE",     "Cross-Site Tracing (XST) attack vector"),
            Map.entry("TRACK",     "Cross-Site Tracing (XST) attack vector"),
            Map.entry("CONNECT",   "Proxy abuse / tunneling attack"),
            Map.entry("DEBUG",     "IIS remote code execution vector"),
            Map.entry("PROPFIND",  "WebDAV enumeration — information disclosure"),
            Map.entry("PROPPATCH", "WebDAV unauthorized modification"),
            Map.entry("MKCOL",     "WebDAV directory creation"),
            Map.entry("COPY",      "WebDAV unauthorized file copy"),
            Map.entry("MOVE",      "WebDAV unauthorized file move"),
            Map.entry("LOCK",      "WebDAV resource locking"),
            Map.entry("UNLOCK",    "WebDAV resource unlocking"),
            Map.entry("SEARCH",    "WebDAV/IIS search enumeration"),
            Map.entry("HEAD",      "Server information gathering"),
            Map.entry("PURGE",     "Cache poisoning attack vector")
    );

    // ══════════════════════════════════════════════════════════════════
    // Password Fields — skip value scan (raw credentials)
    // ══════════════════════════════════════════════════════════════════

    private static final Set<String> PASSWORD_FIELDS = Set.of(
            "password",
            "confirmpassword",
            "newpassword",
            "oldpassword",
            "currentpassword",
            "repeatpassword",
            "secret",
            "pin"
    );

    // ══════════════════════════════════════════════════════════════════
    // Attack Patterns
    // ══════════════════════════════════════════════════════════════════

    // ── XSS ──────────────────────────────────────────────────────────
    private static final Pattern XSS = Pattern.compile(
            "<[^>]*script|javascript:|vbscript:|data:text/html|" +
                    "onload\\s*=|onerror\\s*=|onclick\\s*=|onmouseover\\s*=|" +
                    "onfocus\\s*=|onblur\\s*=|onkeyup\\s*=|onkeydown\\s*=|" +
                    "onsubmit\\s*=|onchange\\s*=|ondblclick\\s*=|" +
                    "eval\\s*\\(|expression\\s*\\(|alert\\s*\\(|confirm\\s*\\(|" +
                    "prompt\\s*\\(|document\\.cookie|document\\.write|" +
                    "window\\.location|<iframe|<object|<embed|<applet|" +
                    "<meta|<link[^>]+href|<svg[^>]*onload|" +
                    "<img[^>]+src[^>]*onerror|" +
                    "innerHTML\\s*=|outerHTML\\s*=|" +
                    "%3Cscript|%3c%73%63%72%69%70%74|" + // URL encoded
                    "&#x3C;script|&#60;script",           // HTML entity encoded
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    // ── SQL Injection ─────────────────────────────────────────────────
    private static final Pattern SQL = Pattern.compile(
            // DDL/DML keywords with context
            "(?i)\\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|" +
                    "EXEC|EXECUTE|TRUNCATE|DECLARE|WAITFOR|SLEEP|BENCHMARK|" +
                    "LOAD_FILE|OUTFILE|DUMPFILE|REPLACE|MERGE)\\b\\s+\\w|" +
                    // Comment sequences
                    "--|#\\s|/\\*[\\s\\S]*?\\*/|/\\*!|" +
                    // Stored procedure patterns
                    "xp_\\w+|sp_\\w+|" +
                    // Hex encoding injection
                    "0x[0-9a-fA-F]{4,}|" +
                    // Schema enumeration
                    "INFORMATION_SCHEMA|SYS\\.TABLES|SYS\\.COLUMNS|" +
                    "SYSOBJECTS|SYSCOLUMNS|PG_SLEEP|PG_TABLES|" +
                    // Tautology with quotes (most reliable SQL injection indicator)
                    "'\\s*(?:OR|AND)\\s+'|" +
                    "\"\\s*(?:OR|AND)\\s+\"|" +
                    "\\)\\s*(?:OR|AND)\\s*\\(|" +
                    // Numeric tautologies
                    "\\b1\\s*=\\s*1\\b|\\b1\\s*=\\s*2\\b|" +
                    "\\b0\\s*=\\s*0\\b|\\bNULL\\s*=\\s*NULL\\b|" +
                    // CHAR/ASCII injection
                    "CHAR\\s*\\(\\s*\\d|ASCII\\s*\\(|" +
                    // UNION-based injection
                    "UNION\\s+(?:ALL\\s+)?SELECT|" +
                    // Blind SQL injection
                    "AND\\s+\\d+\\s*=\\s*\\d+|OR\\s+\\d+\\s*=\\s*\\d+|" +
                    // Time-based blind
                    "SLEEP\\s*\\(|WAITFOR\\s+DELAY|PG_SLEEP\\s*\\(|" +
                    "BENCHMARK\\s*\\(|" +
                    // Error-based
                    "EXTRACTVALUE\\s*\\(|UPDATEXML\\s*\\(|" +
                    // Stacked queries
                    ";\\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|EXEC)",
            Pattern.CASE_INSENSITIVE);

    // ── Path Traversal ────────────────────────────────────────────────
    private static final Pattern PATH_TRAVERSAL = Pattern.compile(
            // Basic traversal
            "\\.{2}[/\\\\]|\\.{2}%2[fF]|\\.{2}%5[cC]|" +
                    // Double encoded
                    "%2[eE]%2[eE][%2fF5cC]+|%252[eE]%252[eE]|" +
                    // Triple encoded
                    "%25%32%65%25%32%65|" +
                    // Unicode encoded
                    "\\.\\.%c0%af|\\.\\.\u00e0\u0080\u00af|" +
                    // Sensitive unix files
                    "/etc/passwd|/etc/shadow|/etc/hosts|/etc/group|" +
                    "/etc/motd|/etc/issue|/proc/self|/proc/version|" +
                    "/var/www|/var/log|/root/|/home/\\w+/|" +
                    // Sensitive windows files
                    "c:/windows|c:\\\\windows|c:/boot\\.ini|" +
                    "c:/winnt|c:/inetpub|c:\\\\inetpub|" +
                    "windows/system32|winnt/system32|" +
                    // Null byte injection
                    "%00|\\x00",
            Pattern.CASE_INSENSITIVE);

    // ── Command Injection ─────────────────────────────────────────────
    private static final Pattern CMD_INJECTION = Pattern.compile(
            // Shell metacharacters with commands
            "[;|&`]\\s*(?:ls|cat|echo|id|whoami|uname|wget|curl|" +
                    "nc|netcat|bash|sh|cmd|powershell|python|perl|ruby|php)|" +
                    // Command substitution
                    "\\$\\(.*?\\)|`[^`]+`|" +
                    // Pipe chaining
                    "\\|\\||&&|>>\\s*/|" +
                    // Common recon commands
                    "\\bping\\s+-[cn]|\\bnslookup\\s|\\bdig\\s|" +
                    "\\bwhoami\\b|\\bid\\b|\\buname\\s+-|" +
                    // File operations
                    "\\bcat\\s+/|\\bls\\s+-|\\bchmod\\s+[0-7]{3}|" +
                    "\\bchown\\s|\\brm\\s+-[rf]|\\bmv\\s+/|\\bcp\\s+/|" +
                    // Network tools
                    "\\bcurl\\s+-|\\bwget\\s+-|\\btelnet\\s|\\bssh\\s|" +
                    // Windows commands
                    "\\bnet\\s+user|\\bipconfig|\\bsysteminfo\\b|" +
                    "\\btasklist\\b|\\bnetstat\\b|" +
                    // Script execution
                    "\\bbash\\s+-[ci]|\\bsh\\s+-[ci]|" +
                    "\\bpowershell\\s+-|\\bcmd\\.exe|" +
                    // Redirection
                    "2>&1|1>&2|>/dev/null|/dev/tcp/",
            Pattern.CASE_INSENSITIVE);

    // ── LDAP Injection ────────────────────────────────────────────────
    private static final Pattern LDAP_INJECTION = Pattern.compile(
            // LDAP filter injection
            "\\(\\s*[|&!]|\\*\\s*\\)|" +
                    // Common LDAP attributes
                    "objectClass=\\*|cn=\\*|uid=\\*|mail=\\*|" +
                    "sn=\\*|givenName=\\*|memberOf=|" +
                    // LDAP URL schemes
                    "\\bldap://|\\bldaps://|\\bldapi://|" +
                    // Null byte in LDAP
                    "\\\\00|\\\\0a|\\\\0d|" +
                    // LDAP metacharacters
                    "\\\\2a|\\\\28|\\\\29|\\\\7c|\\\\26",
            Pattern.CASE_INSENSITIVE);

    // ── XML / XXE Injection ───────────────────────────────────────────
    private static final Pattern XML_INJECTION = Pattern.compile(
            // XXE patterns
            "<!\\[CDATA\\[|<!DOCTYPE[\\s\\S]*?\\[|<!ENTITY|" +
                    "SYSTEM\\s+[\"'][^\"']*[\"']|PUBLIC\\s+[\"']|" +
                    // XML processing instructions
                    "<\\?xml[^>]*\\?>|" +
                    // File inclusion via XXE
                    "file:///|file://|jar://|php://|expect://|" +
                    "gopher://|dict://|ftp://[^\\s]*passwd|" +
                    // SSRF via XML
                    "http://169\\.254\\.169\\.254|" +  // AWS metadata
                    "http://metadata\\.google|" +       // GCP metadata
                    // XML bombs
                    "\\]\\]>|<!\\[IGNORE|<!\\[INCLUDE",
            Pattern.CASE_INSENSITIVE);

    // ── Template Injection (SSTI) ─────────────────────────────────────
    private static final Pattern TEMPLATE_INJECTION = Pattern.compile(
            "\\$\\{.*?\\}|"           +  // Spring/Java EL
                    "#\\{.*?\\}|"             +  // SpEL/Thymeleaf
                    "\\{\\{.*?\\}\\}|"        +  // Jinja2/Twig/Angular
                    "<%[=\\-]?.*?%>|"         +  // ERB/JSP
                    "\\[\\[.*?\\]\\]|"        +  // Thymeleaf
                    "<#.*?>|<@.*?>|"          +  // Freemarker
                    "\\$\\{7\\s*\\*\\s*7\\}|" +  // SSTI test — Spring
                    "\\{\\{7\\s*\\*\\s*7\\}\\}|" + // SSTI test — Jinja2
                    "#\\{7\\s*\\*\\s*7\\}|"   +  // SSTI test — SpEL
                    "\\{\\{config\\}\\}|"     +  // Flask config dump
                    "\\{\\{self\\._dict_\\}\\}|" + // Jinja2 introspection
                    "#\\{T\\(java\\.lang\\.Runtime\\)\\}|" + // Spring RCE
                    "\\$\\{Runtime\\.exec|"   +  // Freemarker RCE
                    "@java\\.lang\\.Runtime", // Groovy/SpEL RCE
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    // ── Header Injection / CRLF ───────────────────────────────────────
    private static final Pattern HEADER_INJECTION = Pattern.compile(
            "\\r\\n|\\r|\\n|" +
                    "%0[dD]%0[aA]|%0[dD]|%0[aA]|" +
                    "%E5%98%8A%E5%98%8D|" + // unicode CRLF
                    "\\\\r\\\\n|\\\\n|\\\\r",
            Pattern.CASE_INSENSITIVE);

    // ── Path Enumeration ──────────────────────────────────────────────
    private static final Pattern PATH_ENUM = Pattern.compile(
            "(?i)/(" +
                    // CMS
                    "wp-admin|wp-login|wp-content|wp-includes|" +
                    "administrator|joomla|drupal|magento|" +
                    // Admin panels
                    "admin|manager|console|dashboard|controlpanel|cpanel|" +
                    "plesk|webmin|phpmyadmin|adminer|" +
                    // Dev/debug tools
                    "actuator|actuator/.*|swagger|swagger-ui|" +
                    "api-docs|v2/api-docs|v3/api-docs|openapi|" +
                    "graphql|graphiql|playground|" +
                    // Config/env files
                    "env|config|configuration|settings|setup|install|" +
                    "\\.env|\\.git|\\.gitignore|\\.svn|\\.htaccess|\\.htpasswd|" +
                    "web\\.config|app\\.config|application\\.properties|" +
                    "application\\.yml|dockerfile|docker-compose|" +
                    // Backup files
                    "backup|bak|old|temp|tmp|" +
                    // Server info
                    "server-status|server-info|nginx-status|" +
                    "phpinfo\\.php|info\\.php|test\\.php|" +
                    // Shells/backdoors
                    "shell\\.php|cmd\\.php|eval\\.php|exec\\.php|" +
                    "c99\\.php|r57\\.php|webshell|backdoor|" +
                    // Sensitive system files
                    "passwd|shadow|group|hosts|" +
                    // Java/Spring specific
                    "elmah\\.axd|trace\\.axd|" +
                    // Cloud metadata
                    "latest/meta-data|metadata/v1|" +
                    // Common API paths probed
                    "console/j_security_check|" +
                    "manager/html|manager/text" +
                    ")",
            Pattern.CASE_INSENSITIVE);

    // ── Open Redirect ─────────────────────────────────────────────────
    private static final Pattern OPEN_REDIRECT = Pattern.compile(
            "(?i)(?:url|redirect|return|goto|next|continue|" +
                    "dest|destination|redir|redirect_uri|" +
                    "redirect_url|return_url|callback|back|link|" +
                    "src|href|target|location)\\s*=\\s*" +
                    "(?:https?://|//|\\\\\\\\|%2f%2f|%252f%252f)" +
                    "(?!(?:localhost|127\\.0\\.0\\.1))",
            Pattern.CASE_INSENSITIVE);

    // ── SSRF Detection ────────────────────────────────────────────────
    private static final Pattern SSRF = Pattern.compile(
            // Internal network ranges
            "(?:https?|ftp|gopher|dict|ldap|jar|expect)://" +
                    "(?:127\\.0\\.0\\.1|0\\.0\\.0\\.0|localhost|" +
                    "10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|" +
                    "172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|" +
                    "192\\.168\\.\\d{1,3}\\.\\d{1,3})|" +
                    // Cloud metadata endpoints
                    "169\\.254\\.169\\.254|" +       // AWS/GCP/Azure metadata
                    "metadata\\.google\\.internal|" +
                    "100\\.100\\.100\\.200|" +        // Alibaba Cloud metadata
                    // URL bypass techniques
                    "0177\\.0\\.0\\.1|0x7f\\.0\\.0\\.1|" + // Octal/hex IP
                    "2130706433|0x7f000001",               // Decimal/hex IP
            Pattern.CASE_INSENSITIVE);

    // ── JSON Injection ────────────────────────────────────────────────
    private static final Pattern JSON_INJECTION = Pattern.compile(
            // JSON structure manipulation
            "\"\\s*:\\s*\\{[^}]*\\}\\s*,\\s*\"(?:admin|role|" +
                    "isAdmin|is_admin|privilege|permission|access)\"\\s*:\\s*true|" +
                    // Prototype pollution
                    "__proto__|prototype\\s*\\[|constructor\\s*\\[|" +
                    "__defineGetter__|__defineSetter__|__lookupGetter__|" +
                    // Mass assignment attempts
                    "\"(?:role|admin|isAdmin|is_admin|" +
                    "privilege|permission|access_level)\"\\s*:\\s*" +
                    "(?:true|1|\"admin\"|\"ADMIN\"|\"superuser\")",
            Pattern.CASE_INSENSITIVE);

    // ── Scanner / Attack Tool User-Agents ─────────────────────────────
    private static final List<String> SCANNER_AGENTS = List.of(
            "sqlmap", "nikto", "nmap", "masscan", "zgrab",
            "dirbuster", "gobuster", "wfuzz", "ffuf",
            "burpsuite", "burp suite", "burp/",
            "nessus", "openvas", "nuclei", "acunetix",
            "appscan", "w3af", "skipfish", "whatweb",
            "metasploit", "msfconsole", "msf/",
            "hydra", "medusa", "zaproxy", "zap/",
            "havij", "pangolin", "jsql", "grabber",
            "vega", "owasp", "paros", "webscarab",
            "arachni", "wapiti", "commix", "beef/",
            "python-requests", "go-http-client",
            "libwww-perl", "lwp-trivial",
            "curl/7.1", "wget/1.1",  // very old versions used by scripts
            "masscan", "zgrab", "shodan"
    );

    // ── Suspicious Patterns ───────────────────────────────────────────
    private static final Pattern SUSPICIOUS = Pattern.compile(
            // Encoded null bytes
            "%00|\\x00|\\u0000|" +
                    // Double/triple encoding
                    "%25(?:%2[fFeE]|%5[cC])|%%|%2525|" +
                    // Unicode normalization bypass
                    "%ef%bc%8f|%e2%80%8f|%c0%ae|%c0%af|" +
                    // IP obfuscation in URLs
                    "https?://0x[0-9a-fA-F]+|" +
                    "https?://[0-9]{8,10}(?:/|$)|" + // decimal IP
                    // Content-type confusion
                    "application/x-www-form-urlencoded.*<script|" +
                    // JWT tampering indicators
                    "eyJ[A-Za-z0-9+/=]{10,}\\.[A-Za-z0-9+/=]{10,}" +
                    "\\.[A-Za-z0-9+/=_-]{0,}(?:alg.*none|HS256.*RS256)",
            Pattern.CASE_INSENSITIVE);

    private static final long MAX_BODY_SIZE = 10 * 1024 * 1024; // 10MB

    // ══════════════════════════════════════════════════════════════════
    // Main Filter
    // ══════════════════════════════════════════════════════════════════

    @Override
    public Mono<Void> filter(ServerWebExchange exchange,
                             GatewayFilterChain chain) {

        ServerHttpRequest request  = exchange.getRequest();
        long              start    = System.currentTimeMillis();

        String ip         = getClientIp(request);
        String path       = request.getPath().value();
        String method     = request.getMethod().name().toUpperCase();
        String userAgent  = request.getHeaders().getFirst("User-Agent");
        String userId     = request.getHeaders().getFirst("X-User-Id");
        String username   = request.getHeaders().getFirst("X-User-Name");
        String role       = request.getHeaders().getFirst("X-User-Role");
        String query      = request.getURI().getRawQuery();
        String referer    = request.getHeaders().getFirst("Referer");
        String origin     = request.getHeaders().getFirst("Origin");
        String protocol   = request.getURI().getScheme();
        Long   contentLen = request.getHeaders().getContentLength() > 0
                ? request.getHeaders().getContentLength() : null;

        EventContext ctx = EventContext.builder()
                .ip(ip).path(path).method(method)
                .userAgent(userAgent).userId(userId)
                .username(username).role(role)
                .query(query).referer(referer)
                .origin(origin).protocol(protocol)
                .contentLength(contentLen)
                .build();

        // ── 1. Block dangerous HTTP methods ───────────────────────────
        if (BLOCKED_METHODS.containsKey(method)) {
            return blockRequest(exchange, ctx,
                    SecurityAuditEvent.ThreatType.HTTP_METHOD_TAMPERING,
                    SecurityAuditEvent.Severity.HIGH,
                    "Blocked HTTP method: " + method
                            + " — " + BLOCKED_METHODS.get(method));
        }

        // ── 2. Block unknown methods ──────────────────────────────────
        if (!ALLOWED_METHODS.contains(method)) {
            return blockRequest(exchange, ctx,
                    SecurityAuditEvent.ThreatType.HTTP_METHOD_TAMPERING,
                    SecurityAuditEvent.Severity.CRITICAL,
                    "Unknown HTTP method: " + method);
        }

        // ── 3. OPTIONS — allow CORS preflight ─────────────────────────
        if ("OPTIONS".equals(method)) {
            return chain.filter(exchange);
        }

        // ── 4. DDoS detection ─────────────────────────────────────────
        if (rateLimitTracker.isDdosSuspected(ip)) {
            return blockRequest(exchange, ctx,
                    SecurityAuditEvent.ThreatType.DDOS_SUSPECTED,
                    SecurityAuditEvent.Severity.CRITICAL,
                    "DDoS suspected — ip: " + ip
                            + " | count: " + rateLimitTracker.getIpCount(ip));
        }

        // ── 5. Rate limit — IP ────────────────────────────────────────
        if (rateLimitTracker.isIpRateLimited(ip)) {
            return blockRequest(exchange, ctx,
                    SecurityAuditEvent.ThreatType.RATE_LIMIT_EXCEEDED,
                    SecurityAuditEvent.Severity.HIGH,
                    "Rate limit exceeded — ip: " + ip
                            + " | count: " + rateLimitTracker.getIpCount(ip));
        }

        // ── 6. Rate limit — User ──────────────────────────────────────
        if (username != null
                && rateLimitTracker.isUserRateLimited(username)) {
            return blockRequest(exchange, ctx,
                    SecurityAuditEvent.ThreatType.RATE_LIMIT_EXCEEDED,
                    SecurityAuditEvent.Severity.HIGH,
                    "Rate limit exceeded — user: " + username);
        }

        // ── 7. Payload size ───────────────────────────────────────────
        if (contentLen != null && contentLen > MAX_BODY_SIZE) {
            return blockRequest(exchange, ctx,
                    SecurityAuditEvent.ThreatType.LARGE_PAYLOAD,
                    SecurityAuditEvent.Severity.HIGH,
                    "Payload too large: " + contentLen + " bytes");
        }

        // ── 8. User-Agent checks ──────────────────────────────────────
        checkUserAgent(userAgent, ctx);

        // ── 9. Header checks ──────────────────────────────────────────
        checkHeaders(request, ctx);

        // ── 10. Path checks ───────────────────────────────────────────
        checkPathThreats(path, ctx);
        checkPathEnumeration(path, ctx);

        // ── 11. CORS check ────────────────────────────────────────────
        checkCors(origin, request, ctx);

        // ── 12. Query param checks ────────────────────────────────────
        if (query != null) {
            checkQueryParams(request, ctx);
            checkOpenRedirect(query, ctx);
            checkSsrf(query, ctx);
        }

        // ── 13. Body inspection ───────────────────────────────────────
        return DataBufferUtils.join(request.getBody())
                .defaultIfEmpty(exchange.getResponse()
                        .bufferFactory().wrap(new byte[0]))
                .flatMap(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer
                            .readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);

                    String body = new String(bytes,
                            StandardCharsets.UTF_8);

                    if (!body.isBlank()) {
                        checkBody(body, ctx);
                    }

                    // ✅ rebuild request with original body
                    DataBufferFactory factory = exchange
                            .getResponse().bufferFactory();
                    DataBuffer newBuffer = factory.wrap(bytes);

                    ServerHttpRequest rebuilt =
                            new ServerHttpRequestDecorator(request) {
                                @Override
                                public Flux<DataBuffer> getBody() {
                                    return Flux.just(newBuffer);
                                }
                            };

                    return chain.filter(exchange.mutate()
                            .request(rebuilt).build());
                })
                .doFinally(signal -> {
                    long elapsed = System.currentTimeMillis() - start;
                    if (elapsed > 30_000) {
                        publishEvent(SecurityAuditEvent.builder()
                                .threatType(SecurityAuditEvent
                                        .ThreatType.SLOW_LORIS)
                                .severity(SecurityAuditEvent
                                        .Severity.MEDIUM)
                                .message("Slow request: "
                                        + elapsed + "ms")
                                .responseTimeMs(elapsed)
                                .blocked(false)
                                .status(SecurityAuditEvent
                                        .AttackStatus.DETECTED)
                                .detectedAt(LocalDateTime.now())
                                .build(), ctx);
                    }
                });
    }

    private void publishEvent(SecurityAuditEvent event, EventContext ctx) {
        SecurityAuditEvent enrichedEvent = SecurityAuditEvent.builder()
                .threatType(event.getThreatType())
                .severity(event.getSeverity())
                .message(event.getMessage())
                .responseTimeMs(event.getResponseTimeMs())
                .blocked(event.isBlocked())
                .status(event.getStatus())
                .detectedAt(event.getDetectedAt())
                .ipAddress(ctx.ip)
                .requestPath(ctx.path)
                .requestMethod(ctx.method)
                .userAgent(ctx.userAgent)
                .userId(ctx.userId)
                .username(ctx.username)
                .userRole(ctx.role)
                .queryString(ctx.query)
                .referer(ctx.referer)
                .origin(ctx.origin)
                .protocol(ctx.protocol)
                .contentLength(ctx.contentLength)
                .serviceId(serviceName)
                .build();

        auditService.recordAsync(enrichedEvent);
    }

    // ══════════════════════════════════════════════════════════════════
    // Block Request
    // ══════════════════════════════════════════════════════════════════

    private Mono<Void> blockRequest(
            ServerWebExchange exchange,
            EventContext ctx,
            SecurityAuditEvent.ThreatType type,
            SecurityAuditEvent.Severity severity,
            String reason) {

        auditService.recordAsync(SecurityAuditEvent.builder()
                .threatType(type)
                .severity(severity)
                .status(SecurityAuditEvent.AttackStatus.BLOCKED)
                .blocked(true)
                .blockReason(reason)
                .ipAddress(ctx.ip)
                .requestPath(ctx.path)
                .requestMethod(ctx.method)
                .userAgent(ctx.userAgent)
                .userId(ctx.userId)
                .username(ctx.username)
                .userRole(ctx.role)
                .queryString(ctx.query)
                .origin(ctx.origin)
                .referer(ctx.referer)
                .protocol(ctx.protocol)
                .contentLength(ctx.contentLength)
                .message(reason)
                .serviceId(serviceName)
                .detectedAt(LocalDateTime.now())
                .build());

        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.FORBIDDEN);
        response.getHeaders().add("Content-Type", "application/json");

        String body = String.format(
                "{\"success\":false,\"code\":\"ACCESS_DENIED\"," +
                        "\"message\":\"Request blocked by security policy\"," +
                        "\"timestamp\":\"%s\"}",
                LocalDateTime.now());

        DataBuffer buffer = response.bufferFactory()
                .wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    // ══════════════════════════════════════════════════════════════════
    // Path Checks
    // ══════════════════════════════════════════════════════════════════

    private void checkPathThreats(String path, EventContext ctx) {
        if (PATH_TRAVERSAL.matcher(path).find())
            publish(SecurityAuditEvent.ThreatType.PATH_TRAVERSAL,
                    SecurityAuditEvent.Severity.HIGH,
                    path, "path", "Path traversal in URL", ctx);

        if (SQL.matcher(path).find())
            publish(SecurityAuditEvent.ThreatType.SQL_INJECTION,
                    SecurityAuditEvent.Severity.CRITICAL,
                    path, "path", "SQL injection in URL", ctx);

        if (CMD_INJECTION.matcher(path).find())
            publish(SecurityAuditEvent.ThreatType.COMMAND_INJECTION,
                    SecurityAuditEvent.Severity.CRITICAL,
                    path, "path", "Command injection in URL", ctx);

        if (XSS.matcher(path).find())
            publish(SecurityAuditEvent.ThreatType.XSS_ATTEMPT,
                    SecurityAuditEvent.Severity.HIGH,
                    path, "path", "XSS in URL", ctx);

        if (SUSPICIOUS.matcher(path).find())
            publish(SecurityAuditEvent.ThreatType.SUSPICIOUS_PATTERN,
                    SecurityAuditEvent.Severity.MEDIUM,
                    path, "path", "Suspicious pattern in URL", ctx);
    }

    private void checkPathEnumeration(String path, EventContext ctx) {
        if (PATH_ENUM.matcher(path).find())
            publish(SecurityAuditEvent.ThreatType.PATH_ENUMERATION,
                    SecurityAuditEvent.Severity.MEDIUM,
                    path, "path",
                    "Sensitive path probe: " + path, ctx);
    }

    // ══════════════════════════════════════════════════════════════════
    // Query Params
    // ══════════════════════════════════════════════════════════════════

    private void checkQueryParams(ServerHttpRequest request,
                                  EventContext ctx) {
        request.getQueryParams().forEach((key, values) ->
                values.forEach(value -> {
                    scanValue(value, "query[" + key + "]", ctx);
                    checkSsrf(value, ctx);
                }));
    }

    private void checkOpenRedirect(String query, EventContext ctx) {
        if (OPEN_REDIRECT.matcher(query).find())
            publish(SecurityAuditEvent.ThreatType.OPEN_REDIRECT,
                    SecurityAuditEvent.Severity.MEDIUM,
                    query, "query",
                    "Open redirect attempt in query", ctx);
    }

    private void checkSsrf(String value, EventContext ctx) {
        if (SSRF.matcher(value).find())
            publish(SecurityAuditEvent.ThreatType.SUSPICIOUS_PATTERN,
                    SecurityAuditEvent.Severity.CRITICAL,
                    value, "ssrf",
                    "SSRF attempt detected", ctx);
    }

    // ══════════════════════════════════════════════════════════════════
    // Body
    // ══════════════════════════════════════════════════════════════════

    private void checkBody(String body, EventContext ctx) {
        // ✅ scan JSON field by field, skip password fields
        if (body.trim().startsWith("{") || body.trim().startsWith("[")) {
            scanJsonBody(body, ctx);
        } else {
            // plain text / form body
            scanValue(body, "body", ctx);
        }

        // ✅ always check these on full body regardless
        if (XML_INJECTION.matcher(body).find())
            publish(SecurityAuditEvent.ThreatType.XML_INJECTION,
                    SecurityAuditEvent.Severity.CRITICAL,
                    truncate(body), "body",
                    "XXE/XML injection in body", ctx);

        if (TEMPLATE_INJECTION.matcher(body).find())
            publish(SecurityAuditEvent.ThreatType.TEMPLATE_INJECTION,
                    SecurityAuditEvent.Severity.HIGH,
                    truncate(body), "body",
                    "Template/SSTI injection in body", ctx);

        if (JSON_INJECTION.matcher(body).find())
            publish(SecurityAuditEvent.ThreatType.JSON_INJECTION,
                    SecurityAuditEvent.Severity.HIGH,
                    truncate(body), "body",
                    "JSON injection / mass assignment in body", ctx);

        if (SSRF.matcher(body).find())
            publish(SecurityAuditEvent.ThreatType.SUSPICIOUS_PATTERN,
                    SecurityAuditEvent.Severity.CRITICAL,
                    truncate(body), "body",
                    "SSRF attempt in body", ctx);
    }

    private void scanJsonBody(String body, EventContext ctx) {
        try {
            // ✅ extract key-value pairs from JSON
            Pattern jsonField = Pattern.compile(
                    "\"([^\"]+)\"\\s*:\\s*" +
                            "(?:\"([^\"]*)\"|(-?\\d+\\.?\\d*)" +
                            "|(true|false|null)" +
                            "|([^,}\\]\"]+))");

            Matcher m = jsonField.matcher(body);
            while (m.find()) {
                String key = m.group(1);

                // find first non-null value group
                String value = null;
                for (int i = 2; i <= 5; i++) {
                    if (m.group(i) != null) {
                        value = m.group(i).trim();
                        break;
                    }
                }

                if (key == null || value == null
                        || value.equals("null")
                        || value.equals("true")
                        || value.equals("false")) continue;

                // ✅ skip password fields — avoid false positives
                if (PASSWORD_FIELDS.contains(
                        key.trim().toLowerCase())) {
                    log.debug("[THREAT-FILTER] Skipping field: {}", key);
                    continue;
                }

                scanValue(value, key, ctx);
            }

        } catch (Exception e) {
            log.debug("[THREAT-FILTER] JSON parse failed, "
                    + "scanning full body");
            scanValue(body, "body", ctx);
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // Value Scanner — runs all patterns on a single value
    // ══════════════════════════════════════════════════════════════════

    private void scanValue(String value, String field,
                           EventContext ctx) {
        if (value == null || value.isBlank()) return;

        if (XSS.matcher(value).find())
            publish(SecurityAuditEvent.ThreatType.XSS_ATTEMPT,
                    SecurityAuditEvent.Severity.HIGH,
                    value, field, "XSS in: " + field, ctx);

        if (SQL.matcher(value).find())
            publish(SecurityAuditEvent.ThreatType.SQL_INJECTION,
                    SecurityAuditEvent.Severity.CRITICAL,
                    value, field,
                    "SQL injection in: " + field, ctx);

        if (CMD_INJECTION.matcher(value).find())
            publish(SecurityAuditEvent.ThreatType.COMMAND_INJECTION,
                    SecurityAuditEvent.Severity.CRITICAL,
                    value, field,
                    "Command injection in: " + field, ctx);

        if (LDAP_INJECTION.matcher(value).find())
            publish(SecurityAuditEvent.ThreatType.LDAP_INJECTION,
                    SecurityAuditEvent.Severity.HIGH,
                    value, field,
                    "LDAP injection in: " + field, ctx);

        if (PATH_TRAVERSAL.matcher(value).find())
            publish(SecurityAuditEvent.ThreatType.PATH_TRAVERSAL,
                    SecurityAuditEvent.Severity.HIGH,
                    value, field,
                    "Path traversal in: " + field, ctx);

        if (TEMPLATE_INJECTION.matcher(value).find())
            publish(SecurityAuditEvent.ThreatType.TEMPLATE_INJECTION,
                    SecurityAuditEvent.Severity.HIGH,
                    value, field,
                    "Template injection in: " + field, ctx);

        if (OPEN_REDIRECT.matcher(value).find())
            publish(SecurityAuditEvent.ThreatType.OPEN_REDIRECT,
                    SecurityAuditEvent.Severity.MEDIUM,
                    value, field,
                    "Open redirect in: " + field, ctx);

        if (SSRF.matcher(value).find())
            publish(SecurityAuditEvent.ThreatType.SUSPICIOUS_PATTERN,
                    SecurityAuditEvent.Severity.CRITICAL,
                    value, field,
                    "SSRF attempt in: " + field, ctx);

        if (SUSPICIOUS.matcher(value).find())
            publish(SecurityAuditEvent.ThreatType.SUSPICIOUS_PATTERN,
                    SecurityAuditEvent.Severity.MEDIUM,
                    value, field,
                    "Suspicious encoding/pattern in: " + field, ctx);
    }

    // ══════════════════════════════════════════════════════════════════
    // Header Checks
    // ══════════════════════════════════════════════════════════════════

    private void checkUserAgent(String userAgent, EventContext ctx) {
        if (userAgent == null || userAgent.isBlank()) {
            publish(SecurityAuditEvent.ThreatType.MISSING_HEADERS,
                    SecurityAuditEvent.Severity.LOW,
                    null, "User-Agent",
                    "Missing User-Agent header", ctx);
            return;
        }

        String lower = userAgent.toLowerCase();

        // ✅ known attack tools
        SCANNER_AGENTS.stream()
                .filter(lower::contains)
                .findFirst()
                .ifPresent(tool ->
                        publish(SecurityAuditEvent.ThreatType.SCANNER_DETECTED,
                                SecurityAuditEvent.Severity.CRITICAL,
                                userAgent, "User-Agent",
                                "Attack tool detected: " + tool, ctx));

        // ✅ CRLF in User-Agent
        if (HEADER_INJECTION.matcher(userAgent).find())
            publish(SecurityAuditEvent.ThreatType.HEADER_INJECTION,
                    SecurityAuditEvent.Severity.HIGH,
                    userAgent, "User-Agent",
                    "CRLF injection in User-Agent", ctx);
    }

    private void checkHeaders(ServerHttpRequest request,
                              EventContext ctx) {
        // ✅ check for missing security headers on non-GET requests
        boolean hasContentType = request.getHeaders()
                .getFirst("Content-Type") != null;
        boolean hasAccept = request.getHeaders()
                .getFirst("Accept") != null;

        if (!hasContentType && !"GET".equals(ctx.method)
                && !"OPTIONS".equals(ctx.method))
            publish(SecurityAuditEvent.ThreatType.MISSING_HEADERS,
                    SecurityAuditEvent.Severity.LOW,
                    null, "Content-Type",
                    "Missing Content-Type header", ctx);

        if (!hasAccept)
            publish(SecurityAuditEvent.ThreatType.MISSING_HEADERS,
                    SecurityAuditEvent.Severity.INFO,
                    null, "Accept",
                    "Missing Accept header", ctx);

        // ✅ scan each header value
        request.getHeaders().forEach((name, values) -> {
            // skip standard safe headers
            if (Set.of("Accept", "Accept-Encoding",
                    "Accept-Language", "Cache-Control",
                    "Connection", "Content-Length",
                    "Content-Type", "Host").contains(name))
                return;

            String combined = String.join("", values);

            if (combined.length() > 8192)
                publish(SecurityAuditEvent.ThreatType.SUSPICIOUS_HEADER,
                        SecurityAuditEvent.Severity.MEDIUM,
                        null, name,
                        "Oversized header: " + name
                                + " (" + combined.length() + " bytes)", ctx);

            if (HEADER_INJECTION.matcher(combined).find())
                publish(SecurityAuditEvent.ThreatType.HEADER_INJECTION,
                        SecurityAuditEvent.Severity.HIGH,
                        truncate(combined), name,
                        "CRLF injection in header: " + name, ctx);

            if (XSS.matcher(combined).find())
                publish(SecurityAuditEvent.ThreatType.XSS_ATTEMPT,
                        SecurityAuditEvent.Severity.HIGH,
                        truncate(combined), name,
                        "XSS in header: " + name, ctx);

            if (SQL.matcher(combined).find())
                publish(SecurityAuditEvent.ThreatType.SQL_INJECTION,
                        SecurityAuditEvent.Severity.CRITICAL,
                        truncate(combined), name,
                        "SQL injection in header: " + name, ctx);
        });
    }

    private void checkCors(String origin,
                           ServerHttpRequest request,
                           EventContext ctx) {
        if (origin == null) return;
        String host = request.getHeaders().getFirst("Host");
        if (host == null) return;

        String hostBase = host.split(":")[0];
        if (!origin.contains(hostBase))
            publish(SecurityAuditEvent.ThreatType.CORS_VIOLATION,
                    SecurityAuditEvent.Severity.MEDIUM,
                    origin, "Origin",
                    "CORS violation — origin: " + origin
                            + " | host: " + host, ctx);
    }

    // ══════════════════════════════════════════════════════════════════
    // Publish + Build
    // ══════════════════════════════════════════════════════════════════

    private void publish(SecurityAuditEvent.ThreatType type,
                         SecurityAuditEvent.Severity severity,
                         String suspiciousValue,
                         String fieldName,
                         String message,
                         EventContext ctx) {

        SecurityAuditEvent event = SecurityAuditEvent.builder()
                .threatType(type)
                .severity(severity)
                .suspiciousValue(truncate(suspiciousValue))
                .fieldName(fieldName)
                .message(message)
                .status(SecurityAuditEvent.AttackStatus.DETECTED)
                .blocked(false)
                .ipAddress(ctx.ip)
                .requestPath(ctx.path)
                .requestMethod(ctx.method)
                .userAgent(ctx.userAgent)
                .userId(ctx.userId)
                .username(ctx.username)
                .userRole(ctx.role)
                .queryString(ctx.query)
                .referer(ctx.referer)
                .origin(ctx.origin)
                .protocol(ctx.protocol)
                .contentLength(ctx.contentLength)
                .serviceId(serviceName)
                .detectedAt(LocalDateTime.now())
                .build();

        auditService.recordAsync(event);
    }

    // ══════════════════════════════════════════════════════════════════
    // Utilities
    // ══════════════════════════════════════════════════════════════════

    private String getClientIp(ServerHttpRequest request) {
        String forwarded = request.getHeaders()
                .getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank())
            return forwarded.split(",")[0].trim();

        String realIp = request.getHeaders().getFirst("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) return realIp;

        String cfIp = request.getHeaders()
                .getFirst("CF-Connecting-IP"); // Cloudflare
        if (cfIp != null && !cfIp.isBlank()) return cfIp;

        if (request.getRemoteAddress() != null)
            return request.getRemoteAddress()
                    .getAddress().getHostAddress();

        return "unknown";
    }

    private String truncate(String value) {
        if (value == null) return null;
        return value.length() > 500
                ? value.substring(0, 500) + "[TRUNCATED]" : value;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 1;
    }

    // ══════════════════════════════════════════════════════════════════
    // Event Context
    // ══════════════════════════════════════════════════════════════════

    @Builder
    @Getter
    static class EventContext {
        String ip, path, method, userAgent;
        String userId, username, role;
        String query, referer, origin, protocol;
        Long contentLength;
    }
}