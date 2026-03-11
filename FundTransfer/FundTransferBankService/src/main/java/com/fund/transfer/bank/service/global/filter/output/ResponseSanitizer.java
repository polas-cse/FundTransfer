package com.fund.transfer.bank.service.global.filter.output;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║                        ResponseSanitizer                                 ║
 * ╠══════════════════════════════════════════════════════════════════════════╣
 * ║ Central output sanitization engine.                                      ║
 * ║ Processes all @SafeOutput annotated fields on response objects           ║
 * ║ before they leave the service.                                           ║
 * ║                                                                          ║
 * ║ Attack vectors covered:                                                  ║
 * ║   Stored XSS via API response    — sanitizeHtml / encodeHtml             ║
 * ║   Log injection / CRLF           — preventLogInjection                   ║
 * ║   JSON injection                 — sanitizeJson                          ║
 * ║   Sensitive data exposure        — hidden / masked / redact              ║
 * ║   Unicode display/smuggling      — normalizeUnicode                      ║
 * ║   Null byte in output            — stripped in sanitizeHtml              ║
 * ║   Nested object fields           — recursive processing                  ║
 * ║   Collection fields (List/Set)   — each element processed                ║
 * ║   Information disclosure         — truncate, maxLength                   ║
 * ║   Role-based field visibility    — visibleToRoles[] matrix               ║
 * ║                                                                          ║
 * ║ USAGE in controller:                                                     ║
 * ║   UserResponse res = userService.getUser(id);                            ║
 * ║   return ResponseEntity.ok(sanitizer.sanitize(res, userRole));           ║
 * ║                                                                          ║
 * ║ USAGE for lists:                                                         ║
 * ║   List<UserResponse> users = userService.getAllUsers();                  ║
 * ║   return ResponseEntity.ok(sanitizer.sanitizeList(users, userRole));     ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */
@Slf4j
@Component
public class ResponseSanitizer {

    // ══════════════════════════════════════════════════════════════════════
    // FIXED REDACTION LABEL
    // Used when redact = true — always outputs this string regardless of role
    // ══════════════════════════════════════════════════════════════════════
    private static final String REDACTED = "[REDACTED]";

    // ══════════════════════════════════════════════════════════════════════
    // XSS / HTML STRIP PATTERN — v2
    // Strips dangerous HTML, script tags, event handlers from output.
    // Same comprehensive pattern as SafeInputValidator for consistency.
    //
    // Catches:
    //  → <script> / </script>
    //  → all on* event handlers (onclick, onload, onerror, ALL 40+ variants)
    //  → javascript: / vbscript: URIs
    //  → data: URIs with text/html payloads
    //  → dangerous tags: <iframe>, <svg>, <embed>, <object>, <form>, <base>
    //  → eval(), expression(), document., window.
    //  → HTML entity-encoded attacks: &#106; &#x6A; \u0041
    //  → null bytes: \x00, %00
    // ══════════════════════════════════════════════════════════════════════
    private static final Pattern HTML_STRIP_PATTERN = Pattern.compile(
            // script tags
            "<[^>]*script[^>]*>|</script[^>]*>"
                    // dangerous tags
                    + "|<\\s*/?(iframe|frame|object|embed|applet|form|base|link|meta|style|svg|math|template)"
                    + "[^>]*>"
                    // all on* event handlers
                    + "|\\bon(load|error|click|dbl[Cc]lick"
                    + "|mouse(?:over|out|enter|leave|move|down|up)"
                    + "|key(?:down|up|press)"
                    + "|focus|blur|change|submit|reset|select"
                    + "|drag(?:start|end|over|enter|leave|drop)?"
                    + "|touch(?:start|end|move|cancel)"
                    + "|animation(?:start|end|iteration)"
                    + "|transition(?:end)?"
                    + "|scroll|resize|copy|cut|paste|context[Mm]enu"
                    + "|pointer(?:down|up|move|enter|leave|cancel)"
                    + "|wheel|input|invalid|search|toggle"
                    + "|before(?:input|unload)|hash[Cc]hange"
                    + "|message|offline|online|pop[Ss]tate"
                    + "|storage|unload|abort)\\s*=\\s*[\"']?[^>\"']*[\"']?"
                    // dangerous protocols and JS sinks
                    + "|javascript[\\s\\u0000]*:"
                    + "|vbscript[\\s]*:"
                    + "|data[\\s]*:[^,]*text/html"
                    + "|eval\\s*\\(|expression\\s*\\("
                    + "|document\\.|window\\."
                    // HTML entity encoding
                    + "|&#[x]?[0-9a-fA-F]+;?"
                    // null bytes
                    + "|\u0000|%00|\\\\u0000|\\\\x00"
                    // any remaining HTML tags (catch-all for strip mode)
                    + "|<[^>]+>",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );

    // ══════════════════════════════════════════════════════════════════════
    // HTML ENCODE CHARACTERS
    // For encodeHtml mode — encode instead of strip
    // Converts dangerous chars to safe HTML entities
    // ══════════════════════════════════════════════════════════════════════
    private static final Pattern AMP_PATTERN   = Pattern.compile("&");
    private static final Pattern LT_PATTERN    = Pattern.compile("<");
    private static final Pattern GT_PATTERN    = Pattern.compile(">");
    private static final Pattern QUOT_PATTERN  = Pattern.compile("\"");
    private static final Pattern APOS_PATTERN  = Pattern.compile("'");
    private static final Pattern SLASH_PATTERN = Pattern.compile("/");

    // ══════════════════════════════════════════════════════════════════════
    // LOG INJECTION — strip CRLF and control characters
    // Strips: \n \r \t and their encoded equivalents
    // Prevents fake log lines from being injected into audit logs
    // ══════════════════════════════════════════════════════════════════════
    private static final Pattern LOG_INJECTION_PATTERN = Pattern.compile(
            "[\\n\\r\\t]|%0[aAdD]|%09|\\\\n|\\\\r|\\\\t",
            Pattern.CASE_INSENSITIVE
    );

    // ══════════════════════════════════════════════════════════════════════
    // JSON INJECTION — escape JSON-breaking characters
    // Jackson already handles most of this, but we add an explicit layer
    // for fields that may be used in template-built JSON strings
    // ══════════════════════════════════════════════════════════════════════
    private static final Pattern JSON_QUOTE_PATTERN     = Pattern.compile("\"");
    private static final Pattern JSON_BACKSLASH_PATTERN = Pattern.compile("\\\\");
    private static final Pattern JSON_NEWLINE_PATTERN   = Pattern.compile("\n");
    private static final Pattern JSON_RETURN_PATTERN    = Pattern.compile("\r");
    private static final Pattern JSON_TAB_PATTERN       = Pattern.compile("\t");

    // ══════════════════════════════════════════════════════════════════════
    // UNICODE CONTROL CHARACTER STRIP
    // Strips non-printable control characters and dangerous unicode
    // U+0000–U+001F : C0 control chars (NUL, BEL, BS, TAB, LF, CR etc.)
    // U+007F         : DEL
    // U+0080–U+009F  : C1 control chars
    // U+200B         : Zero-width space
    // U+200C         : Zero-width non-joiner
    // U+200D         : Zero-width joiner
    // U+202A–U+202E  : Bidirectional text control (RTL override = U+202E)
    // U+2066–U+2069  : Bidirectional isolation marks
    // U+FEFF         : BOM / zero-width no-break space
    // ══════════════════════════════════════════════════════════════════════
    private static final Pattern UNICODE_CONTROL_PATTERN = Pattern.compile(
            "[\u0000-\u001F"       // C0 controls (NUL through US)
                    + "\u007F"             // DEL
                    + "\u0080-\u009F"      // C1 controls
                    + "\u200B-\u200D"      // zero-width spaces and joiners
                    + "\u202A-\u202E"      // bidi control chars (incl. RTL override)
                    + "\u2066-\u2069"      // bidi isolation marks
                    + "\uFEFF"             // BOM / zero-width no-break space
                    + "\\p{Cf}"            // all Unicode format characters
                    + "]"
    );

    // ══════════════════════════════════════════════════════════════════════
    // MAX RECURSION DEPTH — prevents StackOverflow on circular references
    // ══════════════════════════════════════════════════════════════════════
    private static final int MAX_DEPTH = 10;


    // ══════════════════════════════════════════════════════════════════════
    // PUBLIC API — use these methods in controllers / service layer
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Sanitize a single response object with a known role.
     * USAGE:
     *   return ResponseEntity.ok(sanitizer.sanitize(userResponse, userRole));
     */
    public <T> T sanitize(T object, String userRole) {
        if (object == null) return null;

        String resolvedRole = resolveRole(userRole);
        log.debug("[ResponseSanitizer] Sanitizing {} for role: '{}'",
                object.getClass().getSimpleName(), resolvedRole);

        try {
            processFields(object, object.getClass(), resolvedRole, 0);
        } catch (Exception e) {
            log.error("[ResponseSanitizer] Sanitization failed — type: {}, role: {}",
                    object.getClass().getSimpleName(), resolvedRole, e);
        }
        return object;
    }

    /**
     * Sanitize a single response object with NO role (most restrictive).
     * Use for unauthenticated endpoints or when role is unknown.
     */
    public <T> T sanitize(T object) {
        return sanitize(object, null);
    }

    /**
     * Sanitize a list of response objects with a known role.
     * USAGE:
     *   return ResponseEntity.ok(sanitizer.sanitizeList(users, userRole));
     */
    public <T> List<T> sanitizeList(List<T> list, String userRole) {
        if (list == null || list.isEmpty()) return list;
        list.forEach(item -> sanitize(item, userRole));
        return list;
    }

    /**
     * Sanitize a list with NO role (most restrictive).
     */
    public <T> List<T> sanitizeList(List<T> list) {
        return sanitizeList(list, null);
    }


    // ══════════════════════════════════════════════════════════════════════
    // CORE FIELD PROCESSOR — recursive, traverses class hierarchy
    // ══════════════════════════════════════════════════════════════════════

    private void processFields(Object object, Class<?> clazz,
                               String userRole, int depth)
            throws Exception {

        // Guard against StackOverflow on circular object graphs
        if (object == null || clazz == null || clazz == Object.class) return;
        if (depth > MAX_DEPTH) {
            log.warn("[ResponseSanitizer] Max recursion depth ({}) reached — stopping", MAX_DEPTH);
            return;
        }

        for (Field field : clazz.getDeclaredFields()) {
            field.setAccessible(true);
            Object value = field.get(object);

            if (value == null) continue;

            // ── Recurse into nested custom objects ─────────────────────
            // Skips: primitives, wrappers, Strings, Numbers, enums, arrays
            // Recurses into: DTOs, entities, response objects
            if (isCustomObject(value)) {
                processFields(value, value.getClass(), userRole, depth + 1);
                continue;
            }

            // ── Recurse into Collection elements ───────────────────────
            // Handles: List<UserResponse>, Set<OrderDto>, etc.
            if (value instanceof Collection<?> collection) {
                for (Object element : collection) {
                    if (element != null && isCustomObject(element)) {
                        processFields(element, element.getClass(), userRole, depth + 1);
                    }
                }
                continue;
            }

            // ── Recurse into Map values ────────────────────────────────
            // Handles: Map<String, UserResponse>, etc.
            if (value instanceof Map<?, ?> map) {
                for (Object mapValue : map.values()) {
                    if (mapValue != null && isCustomObject(mapValue)) {
                        processFields(mapValue, mapValue.getClass(), userRole, depth + 1);
                    }
                }
                continue;
            }

            // ── Only process @SafeOutput annotated fields ──────────────
            if (!field.isAnnotationPresent(SafeOutput.class)) continue;

            SafeOutput annotation = field.getAnnotation(SafeOutput.class);
            boolean canSee = canRoleSeeFullData(userRole, annotation.visibleToRoles());

            log.debug("[ResponseSanitizer] Field '{}' — role: '{}', canSee: {}",
                    field.getName(), userRole, canSee);

            // ── GATE 1: redact — ALWAYS regardless of role ────────────
            // Must check before everything else.
            // redact = true means NO role ever sees the real value.
            if (annotation.redact()) {
                field.set(object, REDACTED);
                log.debug("[ResponseSanitizer] Field '{}' REDACTED", field.getName());
                continue; // skip all further processing for this field
            }

            // ── GATE 2: hidden — null for unauthorized roles ───────────
            if (annotation.hidden()) {
                if (!canSee) {
                    field.set(object, null);
                    log.debug("[ResponseSanitizer] Field '{}' hidden for role '{}'",
                            field.getName(), userRole);
                }
                continue;
            }

            // ── STRING field processing ───────────────────────────────
            if (value instanceof String str) {
                str = processString(str, annotation, canSee, field.getName());
                field.set(object, str);
                continue;
            }

            // ── NUMBER field processing ───────────────────────────────
            // Numbers don't need HTML/log injection protection but
            // may need hidden/masked behavior for unauthorized roles
            if (value instanceof Number) {
                if (!canSee && !annotation.placeholder().isEmpty()) {
                    field.set(object, annotation.placeholder());
                } else if (!canSee && annotation.masked()) {
                    field.set(object, null); // hide the number entirely
                }
                continue;
            }
        }

        // ── Recurse into parent class fields ──────────────────────────
        processFields(object, clazz.getSuperclass(), userRole, depth + 1);
    }


    // ══════════════════════════════════════════════════════════════════════
    // STRING PIPELINE
    // Applies all enabled transformations in correct priority order
    // ══════════════════════════════════════════════════════════════════════

    private String processString(String str, SafeOutput annotation,
                                 boolean canSee, String fieldName) {

        // ── Step 1: normalizeUnicode ────────────────────────────────────
        // ALWAYS first — normalize before any pattern matching
        // so patterns work correctly on canonical form
        if (annotation.normalizeUnicode()) {
            str = normalizeUnicode(str);
        }

        // ── Step 2: preventLogInjection ────────────────────────────────
        // ALWAYS runs (no role bypass) — strips \n \r \t
        if (annotation.preventLogInjection()) {
            str = preventLogInjection(str);
        }

        // ── Step 3: encodeHtml (takes priority over sanitizeHtml) ──────
        // ALWAYS runs — encode before checking visibility
        // Encodes characters — does NOT strip, safe for display
        if (annotation.encodeHtml()) {
            str = encodeHtml(str);
        }
        // ── Step 4: sanitizeHtml ────────────────────────────────────────
        // ALWAYS runs — strips dangerous HTML/JS patterns
        // Only applied if encodeHtml is NOT enabled (they are mutually exclusive)
        else if (annotation.sanitizeHtml()) {
            str = sanitizeHtml(str);
        }

        // ── Step 5: sanitizeJson ────────────────────────────────────────
        // ALWAYS runs — escapes JSON-breaking chars
        if (annotation.sanitizeJson()) {
            str = sanitizeJson(str);
        }

        // ── Step 6: placeholder (for unauthorized roles) ────────────────
        if (!annotation.placeholder().isEmpty() && !canSee) {
            return annotation.placeholder(); // stop — no further processing
        }

        // ── Step 7: masked (role-based) ─────────────────────────────────
        if (annotation.masked()) {
            if (canSee) {
                log.debug("[ResponseSanitizer] Field '{}' unmasked for authorized role", fieldName);
                return str; // full value for authorized role
            } else {
                String masked = mask(str, annotation.visibleChars());
                log.debug("[ResponseSanitizer] Field '{}' masked", fieldName);
                return masked;
            }
        }

        // ── Step 8: truncate (role-based) ───────────────────────────────
        if (annotation.truncate()) {
            if (!canSee && str.length() > annotation.maxLength()) {
                return str.substring(0, annotation.maxLength()) + "...";
            }
            return str; // authorized role or short enough — return as-is
        }

        // ── Step 9: hard maxLength cap ──────────────────────────────────
        // Safety net — truncate even without truncate=true
        // prevents absurdly long values leaking through
        if (str.length() > annotation.maxLength()) {
            log.warn("[ResponseSanitizer] Field '{}' exceeded maxLength {} — truncating",
                    fieldName, annotation.maxLength());
            return str.substring(0, annotation.maxLength());
        }

        return str;
    }


    // ══════════════════════════════════════════════════════════════════════
    // ROLE RESOLUTION
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Normalize and uppercase the role string.
     * null / blank → null (most restrictive treatment)
     */
    private String resolveRole(String userRole) {
        return (userRole != null && !userRole.isBlank())
                ? userRole.toUpperCase().trim()
                : null;
    }

    /**
     * Determines if the current role can see full (unmasked) field data.
     *
     * Resolution order:
     *  1. null role             → false (always restricted, no exceptions)
     *  2. empty visibleToRoles  → true  (all authenticated roles see full)
     *  3. role in list          → true
     *  4. role not in list      → false
     */
    private boolean canRoleSeeFullData(String userRole, String[] visibleToRoles) {
        // null role = ALWAYS restricted regardless of visibleToRoles config
        if (userRole == null) return false;

        // empty list = no restriction defined = any authenticated role sees full
        if (visibleToRoles == null || visibleToRoles.length == 0) return true;

        // normalize role strings before comparison
        return Arrays.stream(visibleToRoles)
                .map(String::toUpperCase)
                .anyMatch(r -> r.equals(userRole));
    }


    // ══════════════════════════════════════════════════════════════════════
    // SANITIZATION METHODS
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Strips dangerous HTML tags, event handlers, and JS protocols.
     * Used when sanitizeHtml = true (strips content).
     */
    private String sanitizeHtml(String value) {
        if (value == null || value.isBlank()) return value;
        return HTML_STRIP_PATTERN.matcher(value).replaceAll("");
    }

    /**
     * HTML-encodes dangerous characters — preserves visual content.
     * Used when encodeHtml = true (encodes instead of strips).
     * Order matters: & must be first to avoid double-encoding.
     *
     * & → &amp;   (FIRST — prevents double encoding)
     * < → &lt;
     * > → &gt;
     * " → &quot;
     * ' → &#x27;
     * / → &#x2F;  (prevents </script> injection)
     */
    private String encodeHtml(String value) {
        if (value == null || value.isBlank()) return value;
        // & MUST be first — if we did < first, then & in &lt; would get double-encoded
        String encoded = AMP_PATTERN.matcher(value).replaceAll("&amp;");
        encoded = LT_PATTERN.matcher(encoded).replaceAll("&lt;");
        encoded = GT_PATTERN.matcher(encoded).replaceAll("&gt;");
        encoded = QUOT_PATTERN.matcher(encoded).replaceAll("&quot;");
        encoded = APOS_PATTERN.matcher(encoded).replaceAll("&#x27;");
        encoded = SLASH_PATTERN.matcher(encoded).replaceAll("&#x2F;");
        return encoded;
    }

    /**
     * Strips CRLF and tab characters to prevent log injection.
     * Replaces with space so words don't merge.
     * Used when preventLogInjection = true.
     */
    private String preventLogInjection(String value) {
        if (value == null || value.isBlank()) return value;
        return LOG_INJECTION_PATTERN.matcher(value).replaceAll(" ").trim();
    }

    /**
     * Escapes JSON-breaking characters.
     * Extra safety layer on top of Jackson's own escaping.
     * Used when sanitizeJson = true.
     *
     * Order matters:
     *  1. backslash first — so we don't double-escape later escapes
     *  2. then quote, newline, return, tab
     */
    private String sanitizeJson(String value) {
        if (value == null || value.isBlank()) return value;
        // backslash FIRST — avoids double-escaping
        String escaped = JSON_BACKSLASH_PATTERN.matcher(value).replaceAll("\\\\\\\\");
        escaped = JSON_QUOTE_PATTERN.matcher(escaped).replaceAll("\\\\\"");
        escaped = JSON_NEWLINE_PATTERN.matcher(escaped).replaceAll("\\\\n");
        escaped = JSON_RETURN_PATTERN.matcher(escaped).replaceAll("\\\\r");
        escaped = JSON_TAB_PATTERN.matcher(escaped).replaceAll("\\\\t");
        return escaped;
    }

    /**
     * Normalizes unicode to NFC form and strips dangerous control characters.
     * NFC = Canonical Decomposition, followed by Canonical Composition.
     * Used when normalizeUnicode = true.
     *
     * Example:
     *  "cafe\u0301" (e + combining accent) → "café" (single precomposed char)
     *  "Hello\u202EWorld"                  → "HelloWorld" (RTL override stripped)
     *  "test\u200Bvalue"                   → "testvalue"  (zero-width space stripped)
     */
    private String normalizeUnicode(String value) {
        if (value == null || value.isBlank()) return value;
        // Normalize to NFC — canonical form
        String normalized = Normalizer.normalize(value, Normalizer.Form.NFC);
        // Strip dangerous control characters
        return UNICODE_CONTROL_PATTERN.matcher(normalized).replaceAll("");
    }

    /**
     * Masks a string — replaces all but the last N characters with '*'.
     * If the string is shorter than visibleChars, masks the entire thing.
     *
     * Examples (visibleChars = 4):
     *   "1234567890123456" → "************3456"
     *   "john@gmail.com"   → "**********l.com"
     *   "abc"              → "***"  (shorter than visibleChars)
     */
    private String mask(String value, int visibleChars) {
        if (value == null) return null;
        if (value.length() <= visibleChars)
            return "*".repeat(value.length()); // mask entire string
        return "*".repeat(value.length() - visibleChars)
                + value.substring(value.length() - visibleChars);
    }


    // ══════════════════════════════════════════════════════════════════════
    // OBJECT TYPE DETECTION
    // Determines whether to recurse into an object or skip it
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Returns true for custom DTO/entity objects that should be recursed into.
     * Returns false for primitives, wrappers, Strings, Numbers, enums, etc.
     *
     * Safe to recurse: UserResponse, BankDto, TransactionResponse, etc.
     * Skip recursion: Integer, String, Boolean, Long, Double, Enum, array
     */
    private boolean isCustomObject(Object obj) {
        if (obj == null) return false;
        Class<?> clazz = obj.getClass();

        return !clazz.isPrimitive()
                && !clazz.isEnum()
                && !clazz.isArray()
                && !clazz.getName().startsWith("java.")
                && !clazz.getName().startsWith("javax.")
                && !clazz.getName().startsWith("jakarta.")
                && !clazz.getName().startsWith("org.springframework.")
                && !clazz.getName().startsWith("com.fasterxml.")
                && !(obj instanceof Number)
                && !(obj instanceof String)
                && !(obj instanceof Boolean)
                && !(obj instanceof Character)
                && !(obj instanceof Collection)
                && !(obj instanceof Map);
    }
}