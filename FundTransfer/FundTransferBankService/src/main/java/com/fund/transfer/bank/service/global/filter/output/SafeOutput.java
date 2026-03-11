package com.fund.transfer.bank.service.global.filter.output;

import java.lang.annotation.*;

/**
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║                        @SafeOutput Annotation                            ║
 * ╠══════════════════════════════════════════════════════════════════════════╣
 * ║ Controls what data leaves the service and in what form.                  ║
 * ║ Apply to response DTO/entity fields to protect against:                  ║
 * ║                                                                          ║
 * ║  • Data exposure     — hidden, masked, placeholder, redact               ║
 * ║  • XSS in output     — sanitizeHtml, encodeHtml                          ║
 * ║  • Log injection     — preventLogInjection (strips CRLF)                 ║
 * ║  • JSON injection    — sanitizeJson                                      ║
 * ║  • Sensitive leakage — redact (hard replace with [REDACTED])             ║
 * ║  • Unicode attacks   — normalizeUnicode                                  ║
 * ║  • Info disclosure   — truncate, maxLength                               ║
 * ║                                                                          ║
 * ╠══════════════════════════════════════════════════════════════════════════╣
 * ║ ROLE MATRIX:                                                             ║
 * ║  null role      → ALWAYS most restrictive (no exceptions)                ║
 * ║  empty roles[]  → all authenticated roles see full data                  ║
 * ║  roles defined  → only listed roles see full data                        ║
 * ║                                                                          ║
 * ║ ATTACK SURFACE COVERED:                                                  ║
 * ║  XSS via API response  → sanitizeHtml / encodeHtml                       ║
 * ║  Log forging/injection → preventLogInjection                             ║
 * ║  JSON injection        → sanitizeJson                                    ║
 * ║  Sensitive data leak   → hidden / masked / redact                        ║
 * ║  Unicode smuggling     → normalizeUnicode                                ║
 * ║  CRLF injection        → preventLogInjection                             ║
 * ║  Null byte in output   → sanitizeHtml (strips \x00)                      ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */
@Documented
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface SafeOutput {

    // ══════════════════════════════════════════════════════════════════════
    // VISIBILITY / ACCESS CONTROL
    // Controls whether the field is visible at all and to whom
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Completely removes the field from output for unauthorized roles.
     * Sets the field value to null when the role is not in visibleToRoles[].
     * WHY: Prevent internal IDs, flags, or metadata leaking to end users.
     * HOW:
     *   @SafeOutput(hidden = true, visibleToRoles = {"ADMIN"})
     *   private Long internalId;
     *   USER  → null     ← hidden
     *   ADMIN → 1001     ← visible
     */
    boolean hidden() default false;

    /**
     * Completely and permanently replaces field value with a fixed label.
     * Unlike hidden() which nulls the field, redact() always outputs "[REDACTED]"
     * regardless of role — even ADMIN sees "[REDACTED]".
     * WHY: Passwords, raw keys, secrets should NEVER be in any response.
     *   Use for fields that should never travel in any response to any caller.
     * HOW:
     *   @SafeOutput(redact = true)
     *   private String rawPassword;
     *   ALL roles → "[REDACTED]"
     */
    boolean redact() default false;

    /**
     * Masks string value — replaces most characters with '*'.
     * visibleChars controls how many trailing characters stay visible.
     * WHY: Show partial data (last 4 digits) without exposing full value.
     * HOW:
     *   @SafeOutput(masked = true, visibleChars = 4, visibleToRoles = {"ADMIN"})
     *   private String accountNumber;
     *   USER  → "************3456"
     *   ADMIN → "1234567890123456"
     */
    boolean masked() default false;

    /**
     * Number of trailing characters to keep visible when masked = true.
     * DEFAULT: 4 (shows last 4 digits — standard for payment cards)
     */
    int visibleChars() default 4;

    /**
     * Replaces the field value with a fixed placeholder string for
     * unauthorized roles instead of masking or nulling.
     * WHY: Provide a descriptive placeholder rather than null.
     * HOW:
     *   @SafeOutput(placeholder = "***-***-****")
     *   private String phone;
     *   USER  → "***-***-****"
     *   ADMIN → "+8801712345678" (original)
     */
    String placeholder() default "";

    /**
     * Defines WHICH roles can see the full unmodified field value.
     * Everyone NOT in this list gets masked / hidden / placeholder applied.
     * null role is ALWAYS restricted regardless of this list.
     *
     * EXAMPLES:
     *   visibleToRoles = {}                 → all authenticated roles see full
     *   visibleToRoles = {"ADMIN"}          → only ADMIN sees full, others masked
     *   visibleToRoles = {"ADMIN","SUPER"}  → ADMIN and SUPER see full
     *
     * ROLE RESOLUTION ORDER:
     *   1. null role                      → always restricted (no exceptions)
     *   2. redact = true                  → always "[REDACTED]" (no exceptions)
     *   3. visibleToRoles is empty        → all authenticated roles see full
     *   4. role is in visibleToRoles[]    → full data
     *   5. role is NOT in visibleToRoles[]→ masked/hidden/placeholder applied
     */
    String[] visibleToRoles() default {};


    // ══════════════════════════════════════════════════════════════════════
    // TRUNCATION
    // Limits how much text is revealed in output
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Truncates long string values to maxLength characters for unauthorized roles.
     * WHY: Prevent full sensitive text (addresses, notes, descriptions)
     *      from being returned to users without sufficient privileges.
     * HOW:
     *   @SafeOutput(truncate = true, maxLength = 20, visibleToRoles = {"ADMIN"})
     *   private String notes;
     *   USER  → "This is a partial..." (20 chars + "...")
     *   ADMIN → "This is a full note with all details" (full)
     */
    boolean truncate() default false;

    /**
     * Maximum character length when truncate = true.
     * Also used as general output length cap when truncate = false
     * (additional safety net against huge values in responses).
     * DEFAULT: 255
     */
    int maxLength() default 255;


    // ══════════════════════════════════════════════════════════════════════
    // XSS / HTML PROTECTION IN OUTPUT
    // Prevents injected HTML/JS from being echoed back in API responses
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Strips dangerous HTML/JS from the output value.
     * WHY: If attacker stored XSS payload in DB ("name": "<script>alert(1)</script>"),
     *      it must be stripped before echoing in any API response.
     * HOW:
     *   @SafeOutput(sanitizeHtml = true)  ← removes tags
     *   private String name;
     *   Stored: "<script>alert(1)</script>John"
     *   Output: "John"
     *
     * NOTE: sanitizeHtml ALWAYS runs — cannot be bypassed by any role.
     *       Even ADMIN gets sanitized output.
     * NOTE: Use encodeHtml = true instead if you want to preserve
     *       the content visually (e.g. in a rich text preview).
     */
    boolean sanitizeHtml() default false;

    /**
     * HTML-encodes dangerous characters instead of stripping them.
     * Converts: < → &lt;  > → &gt;  " → &quot;  & → &amp;  ' → &#x27;
     * WHY: Safe alternative to sanitizeHtml when the text should
     *      still be visible but not executable.
     * HOW:
     *   @SafeOutput(encodeHtml = true)
     *   private String comment;
     *   Stored: "<script>alert(1)</script>"
     *   Output: "&lt;script&gt;alert(1)&lt;/script&gt;"
     *           → shown in browser as text, not executed as code
     *
     * NOTE: encodeHtml takes priority over sanitizeHtml if both are true.
     * NOTE: encodeHtml ALWAYS runs — cannot be bypassed by role.
     */
    boolean encodeHtml() default false;


    // ══════════════════════════════════════════════════════════════════════
    // LOG INJECTION PREVENTION
    // Prevents CRLF / newline injection via output values into log files
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Strips carriage return (\r), newline (\n), and tab (\t) characters.
     * WHY: Log injection — if an attacker stores "user\nINFO: Admin login success"
     *      and this value is logged, it appears as a fake legitimate log entry.
     *      This can:
     *        → Forge audit trail entries
     *        → Confuse security monitoring / SIEM tools
     *        → Bypass log analysis tools looking for patterns
     * HOW:
     *   @SafeOutput(preventLogInjection = true)
     *   private String username;
     *   Stored: "john\nINFO: Admin granted to john"
     *   Output: "johnINFO: Admin granted to john"  ← newline stripped
     *   Log:    "User: johnINFO: Admin granted to john" ← cannot forge new line
     *
     * NOTE: Always enable for any field that appears in logs.
     * NOTE: ALWAYS runs — cannot be bypassed by role.
     */
    boolean preventLogInjection() default false;


    // ══════════════════════════════════════════════════════════════════════
    // JSON INJECTION PREVENTION
    // Prevents breaking out of JSON string context in API responses
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Escapes JSON-breaking characters in string output values.
     * WHY: If a stored value contains raw quotes or backslashes,
     *      it can break JSON structure or inject additional JSON fields.
     *      Example payload: storedName = 'evil", "isAdmin": true, "x": "'
     *      Unescaped output: {"name": "evil", "isAdmin": true, "x": ""}
     *      → Client reads isAdmin=true even though it was never set!
     * Escapes: " → \"   \ → \\   / → \/  (in addition to what JSON serializer does)
     * HOW:
     *   @SafeOutput(sanitizeJson = true)
     *   private String name;
     *
     * NOTE: Most JSON serializers (Jackson) already escape these.
     *       Enable this as an extra layer if using manual string building
     *       or if values are embedded in JSON template strings.
     * NOTE: ALWAYS runs — cannot be bypassed by role.
     */
    boolean sanitizeJson() default false;


    // ══════════════════════════════════════════════════════════════════════
    // UNICODE NORMALIZATION
    // Prevents unicode-based smuggling and display attacks
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Normalizes unicode characters to NFC form and strips non-printable
     * control characters from the output value.
     * WHY:
     *   1. Unicode control chars (U+200B zero-width space, U+202E right-to-left
     *      override) can reverse text visually in browsers.
     *      e.g. "amount: ‮999" displayed as "amount: 999‮" (reversal attack)
     *   2. Non-printable chars (U+0000–U+001F, U+007F–U+009F) can:
     *      → corrupt log parsers
     *      → bypass string length checks
     *      → cause rendering issues in frontend
     *   3. Zero-width joiners/non-joiners can hide characters in strings.
     * HOW:
     *   @SafeOutput(normalizeUnicode = true)
     *   private String description;
     *   Stored: "Hello\u202EWorld"  ← right-to-left override
     *   Output: "HelloWorld"        ← control char stripped
     *
     * NOTE: ALWAYS runs — cannot be bypassed by role.
     * NOTE: Enable for any user-generated text displayed in browser or logged.
     */
    boolean normalizeUnicode() default false;
}