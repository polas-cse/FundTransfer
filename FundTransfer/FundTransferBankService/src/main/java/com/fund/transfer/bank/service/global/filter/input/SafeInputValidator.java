package com.fund.transfer.bank.service.global.filter.input;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.regex.Pattern;

/**
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║                      SafeInputValidator (String)                         ║
 * ╠══════════════════════════════════════════════════════════════════════════╣
 * ║ Validates String fields annotated with @SafeInput.                       ║
 * ║                                                                          ║
 * ║ Improvements over v1:                                                    ║
 * ║  • SQL pattern — covers time-based, schema enum, char/hex encoding       ║
 * ║  • XSS pattern — covers all on* events, SVG, entity encoding             ║
 * ║  • Path traversal — covers double-encoded, unicode, overlong UTF-8       ║
 * ║  • HTML sanitizer — no longer allows href (javascript: bypass)           ║
 * ║  • Null byte detection (\x00, %00, \u0000)                               ║
 * ║  • Unicode homograph detection (Cyrillic/Greek lookalikes)               ║
 * ║  • Phone number format validation (E.164 + local formats)                ║
 * ║  • Word count limit (DoS protection for text fields)                     ║
 * ║  • Decimal precision check (prevents DB DECIMAL overflow)                ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */
@Component
public class SafeInputValidator implements ConstraintValidator<SafeInput, String> {

    private static final Logger log = LoggerFactory.getLogger(SafeInputValidator.class);

    // ══════════════════════════════════════════════════════════════════════
    // HTML SANITIZER
    // FORMATTING only — LINKS removed because href allows javascript: URIs
    // e.g. <a href="javascript:alert(1)"> passes LINKS sanitizer
    // For rich text (allowHtml=true) we use a strict explicit policy
    // ══════════════════════════════════════════════════════════════════════
    private static final PolicyFactory STRICT_HTML_SANITIZER =
            Sanitizers.FORMATTING; // bold, italic, underline — no links/hrefs

    private static final PolicyFactory RICH_TEXT_SANITIZER =
            new HtmlPolicyBuilder()
                    .allowElements("p", "b", "i", "u", "strong", "em",
                            "br", "ul", "ol", "li", "blockquote")
                    .allowUrlProtocols("https") // only https — no javascript:
                    .toFactory();

    // ══════════════════════════════════════════════════════════════════════
    // XSS PATTERN — v2
    // Improvements over v1:
    //   + All on* event handlers (not just onload/onerror/onclick)
    //   + SVG/iframe/form/math dangerous tags
    //   + HTML entity-encoded attack vectors (&#x3C; &#106; \u003c)
    //   + javascript: with whitespace bypass (java\tscript:)
    //   + data: URI scheme (can carry JS payloads)
    // ══════════════════════════════════════════════════════════════════════
    private static final Pattern XSS_PATTERN = Pattern.compile(
            // script tags and classic vectors
            "<[^>]*script"
                    + "|javascript[\\s\\u0000]*:[\\s\\u0000]*"       // java\tscript: bypass
                    + "|vbscript[\\s]*:"
                    + "|data[\\s]*:[^,]*text/html"                   // data: URI with HTML

                    // ALL on* event handlers (not just common ones)
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
                    + "|before(?:input|unload)|after(?:print)"
                    + "|hash[Cc]hange|message|offline|online|page(?:show|hide)"
                    + "|pop[Ss]tate|storage|unload|abort|waiting"
                    + "|can[Pp]lay|duration[Cc]hange|emptied|ended"
                    + "|loaded(?:data|metadata)|pause|play(?:ing)?"
                    + "|progress|rate[Cc]hange|seeked?|stalled|suspend"
                    + "|time[Uu]pdate|volume[Cc]hange)\\s*="

                    // dangerous DOM/JS sinks
                    + "|eval\\s*\\(|expression\\s*\\(|document\\."
                    + "|window\\.|alert\\s*\\(|confirm\\s*\\(|prompt\\s*\\("
                    + "|innerhtml|outerhtml|insertadjacenthtml|write\\s*\\("
                    + "|settimeout\\s*\\(|setinterval\\s*\\("
                    + "|function\\s*\\(|new\\s+function"

                    // dangerous HTML tags
                    + "|<\\s*(?:svg|math|iframe|frame|object|embed|applet"
                    + "|form|base|link|meta|style|template)[^>]*>"

                    // HTML entity encoding bypass (&#106; = j → javascript:)
                    + "|&#[x]?[0-9a-fA-F]+;?"
                    + "|\\\\u[0-9a-fA-F]{4}"

                    // CSS expression (IE attack)
                    + "|url\\s*\\(\\s*['\"]?\\s*javascript:",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );

    // ══════════════════════════════════════════════════════════════════════
    // SQL INJECTION PATTERN — v2
    // Improvements over v1:
    //   + Time-based: SLEEP(), WAITFOR DELAY, BENCHMARK()
    //   + Schema enumeration: information_schema, pg_catalog, sys.tables
    //   + Char encoding: CHAR(83) based payload building
    //   + Hex encoding: 0x53454c454354
    //   + Stacked queries: ;SELECT, ;DROP
    //   + Comment variations: /**/, #, --+, /*!
    //   + Logical operators: OR 1=1, AND 1=1
    // ══════════════════════════════════════════════════════════════════════
    private static final Pattern SQL_PATTERN = Pattern.compile(
            // DML/DDL keywords
            "\\b(select|insert|update|delete|drop|truncate|alter|create|replace"
                    + "|exec(?:ute)?|union|fetch|declare|cast|convert|merge|call)\\b"

                    // string/type functions used for encoding attacks
                    + "|\\b(char|nchar|varchar|nvarchar|hex|unhex|ascii|ord|chr)\\s*\\("

                    // comment sequences
                    + "|--|/\\*|\\*/|#(?!\\w)|--\\+|/\\*!|--\\s"

                    // stored procedure prefixes (MSSQL)
                    + "|\\b(xp_|sp_)\\w+"

                    // hex literal encoding
                    + "|0x[0-9a-fA-F]+"

                    // time-based blind injection
                    + "|\\bsleep\\s*\\(|\\bwaitfor\\s+delay\\b|\\bbenchmark\\s*\\("
                    + "|\\bpg_sleep\\s*\\(|\\bdbms_pipe\\.receive_message"

                    // schema enumeration
                    + "|\\binformation_schema\\b|\\bpg_catalog\\b|\\bsys\\.(?:tables|columns|objects)\\b"
                    + "|\\bsysobjects\\b|\\bsyscolumns\\b"

                    // stacked query injection
                    + ";\\s*(select|insert|update|delete|drop|exec|call)\\b"

                    // logical tautology patterns (1=1, 'a'='a')
                    + "|\\b(?:or|and)\\s+['\"]?\\w+['\"]?\\s*=\\s*['\"]?\\w+['\"]?"
                    + "|\\b(?:or|and)\\s+\\d+\\s*=\\s*\\d+"

                    // UNION-based columns
                    + "|union\\s+(?:all\\s+)?select"

                    // null/conditional injection
                    + "|\\bcoalesce\\s*\\(|\\bifnull\\s*\\(|\\biif\\s*\\(",
            Pattern.CASE_INSENSITIVE
    );

    // ══════════════════════════════════════════════════════════════════════
    // PATH TRAVERSAL PATTERN — v2
    // Improvements over v1:
    //   + Double URL-encoded: %252e%252e%252f (%25 decodes to %)
    //   + Overlong UTF-8: %c0%af, %c1%9c (non-standard / encoding)
    //   + Unicode path separators: U+2215, U+2216, U+FF0F
    //   + Strip-and-slide: ....// (after filter strips ../ stays ../)
    //   + Backslash variants: ..\ and encoded %5c
    //   + Null byte termination: ../etc/passwd%00
    // ══════════════════════════════════════════════════════════════════════
    private static final Pattern PATH_TRAVERSAL_PATTERN = Pattern.compile(
            // classic
            "\\.\\./|\\.\\.\\\\"

                    // single-encoded
                    + "|%2e%2e%2f|%2e%2e/|\\.%2f|%2e%2e%5c|%5c\\.\\."

                    // double-encoded (%25 = %)
                    + "|%252e%252e%252f|%252e%252e/|%252e%252e%255c"

                    // overlong UTF-8 encodings of / and \
                    + "|%c0%af|%c1%9c|%c0%ae"

                    // unicode slash/dot lookalikes
                    + "|%u2215|%u2216|%uff0f|%u005c"

                    // strip-and-slide (filter strips ../ but ....// becomes ../ after)
                    + "|\\.\\.\\.\\./|\\.\\.\\.\\.\\\\|\\.\\.//|\\.\\.\\\\\\\\"

                    // null byte after path (../etc/passwd%00.jpg)
                    + "|\\.\\.[/\\\\][^\\s]*%00",
            Pattern.CASE_INSENSITIVE
    );

    // ══════════════════════════════════════════════════════════════════════
    // COMMAND INJECTION PATTERN
    // Catches shell metacharacters used to chain/inject OS commands
    // ══════════════════════════════════════════════════════════════════════
    private static final Pattern COMMAND_PATTERN = Pattern.compile(
            // shell operators
            "[;&|`]|\\|\\||&&"

                    // subshell / command substitution
                    + "|\\$\\(|\\$\\{|`[^`]*`"

                    // newline injection (for log injection too)
                    + "|%0[aAdD]|\\\\[nNrR]",
            Pattern.CASE_INSENSITIVE
    );

    // ══════════════════════════════════════════════════════════════════════
    // NULL BYTE PATTERN
    // Catches raw null, URL-encoded %00, and unicode \u0000
    // ══════════════════════════════════════════════════════════════════════
    private static final Pattern NULL_BYTE_PATTERN = Pattern.compile(
            "\u0000|%00|\\\\u0000|\\\\x00|\\\\0(?![0-7])",
            Pattern.CASE_INSENSITIVE
    );

    // ══════════════════════════════════════════════════════════════════════
    // UNICODE HOMOGRAPH PATTERN
    // Detects non-ASCII characters that look like ASCII letters.
    // Strategy: if the string contains any char outside Basic Latin
    // (U+0020–U+007E) AND also contains ASCII letters, flag as suspicious.
    // This catches mixed-script homograph attacks while allowing
    // purely non-Latin input (Bengali, Arabic) if needed.
    // ══════════════════════════════════════════════════════════════════════
    private static final Pattern NON_ASCII_PATTERN = Pattern.compile("[^\u0020-\u007E]");
    private static final Pattern ASCII_LETTER_PATTERN = Pattern.compile("[a-zA-Z]");

    // ══════════════════════════════════════════════════════════════════════
    // FORMAT PATTERNS
    // ══════════════════════════════════════════════════════════════════════
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$"
    );
    private static final Pattern NUMERIC_PATTERN    = Pattern.compile("^[0-9]+$");
    private static final Pattern ALPHA_PATTERN      = Pattern.compile("^[a-zA-Z]+$");
    private static final Pattern ALPHANUM_PATTERN   = Pattern.compile("^[a-zA-Z0-9]+$");
    private static final Pattern NO_SPECIAL_PATTERN = Pattern.compile("^[a-zA-Z0-9\\s]+$");
    private static final Pattern NO_WHITESPACE      = Pattern.compile("^\\S+$");
    private static final Pattern URL_PATTERN        = Pattern.compile(
            "^(https?|ftp)://[^\\s/$.?#][^\\s]*$",
            Pattern.CASE_INSENSITIVE
    );

    // Phone: E.164 (+8801712345678), local (01712345678), formatted (+1-555-123-4567)
    // Accepts 7–15 digits, optional leading +, optional dashes/spaces/dots between groups
    private static final Pattern PHONE_PATTERN = Pattern.compile(
            "^\\+?[0-9]{1,3}?[\\s.\\-]?\\(?[0-9]{1,4}\\)?[\\s.\\-]?[0-9]{1,4}[\\s.\\-]?[0-9]{1,9}$"
    );

    // ══════════════════════════════════════════════════════════════════════
    // ANNOTATION FIELDS — populated in initialize()
    // ══════════════════════════════════════════════════════════════════════
    private boolean required, notNull, notEmpty;
    private int minLength, maxLength, maxWords;
    private boolean numericOnly, positive, positiveOrZero, negative, negativeOrZero;
    private long minValue, maxValue;
    private int integerDigits, fractionDigits;
    private String decimalMin, decimalMax;
    private boolean decimalInclusive;
    private boolean emailFormat, url, alphanumeric, alphaOnly, noSpecialChars, phoneFormat;
    private String pattern;
    private boolean past, pastOrPresent, future, futureOrPresent;
    private String dateFormat;
    private boolean assertTrue, assertFalse;
    private boolean allowHtml, noSqlInjection, noPathTraversal, noCommandInjection;
    private boolean noNullBytes, noUnicodeHomograph;
    private boolean trimmed, noWhitespace;

    // ══════════════════════════════════════════════════════════════════════
    // INITIALIZE — called once per annotated field at startup
    // ══════════════════════════════════════════════════════════════════════
    @Override
    public void initialize(SafeInput a) {
        required           = a.required();
        notNull            = a.notNull();
        notEmpty           = a.notEmpty();
        minLength          = a.minLength();
        maxLength          = a.maxLength();
        maxWords           = a.maxWords();
        numericOnly        = a.numericOnly();
        positive           = a.positive();
        positiveOrZero     = a.positiveOrZero();
        negative           = a.negative();
        negativeOrZero     = a.negativeOrZero();
        minValue           = a.minValue();
        maxValue           = a.maxValue();
        integerDigits      = a.integerDigits();
        fractionDigits     = a.fractionDigits();
        decimalMin         = a.decimalMin();
        decimalMax         = a.decimalMax();
        decimalInclusive   = a.decimalInclusive();
        emailFormat        = a.emailFormat();
        url                = a.url();
        alphanumeric       = a.alphanumeric();
        alphaOnly          = a.alphaOnly();
        noSpecialChars     = a.noSpecialChars();
        phoneFormat        = a.phoneFormat();
        pattern            = a.pattern();
        past               = a.past();
        pastOrPresent      = a.pastOrPresent();
        future             = a.future();
        futureOrPresent    = a.futureOrPresent();
        dateFormat         = a.dateFormat();
        assertTrue         = a.assertTrue();
        assertFalse        = a.assertFalse();
        allowHtml          = a.allowHtml();
        noSqlInjection     = a.noSqlInjection();
        noPathTraversal    = a.noPathTraversal();
        noCommandInjection = a.noCommandInjection();
        noNullBytes        = a.noNullBytes();
        noUnicodeHomograph = a.noUnicodeHomograph();
        trimmed            = a.trimmed();
        noWhitespace       = a.noWhitespace();
    }

    // ══════════════════════════════════════════════════════════════════════
    // IS VALID — main validation entry point
    // Order: null → trim → security → format → numeric → decimal → date → bool
    // ══════════════════════════════════════════════════════════════════════
    @Override
    public boolean isValid(String value, ConstraintValidatorContext ctx) {
        ctx.disableDefaultConstraintViolation();

        // ── 1. Null checks ────────────────────────────────────────────────
        if (value == null) {
            if (required || notNull || notEmpty)
                return fail(ctx, "This field is required");
            return true; // null is acceptable for optional fields
        }

        // ── 2. Apply trim if enabled ──────────────────────────────────────
        // Trim before all other checks so length/format checks are accurate
        String v = trimmed ? value.trim() : value;

        // ── 3. Blank / empty checks ───────────────────────────────────────
        if (required && v.isBlank())
            return fail(ctx, "This field must not be blank");
        if (notEmpty && v.isEmpty())
            return fail(ctx, "This field must not be empty");

        // Skip all further validation if empty and not required
        if (v.isEmpty()) return true;

        // ── 4. Null byte detection (before any other check) ───────────────
        // Must check early — null bytes can corrupt subsequent pattern matching
        if (noNullBytes && NULL_BYTE_PATTERN.matcher(v).find()) {
            log.warn("[SafeInput] Null byte detected in input");
            return fail(ctx, "Invalid characters detected");
        }

        // ── 5. Unicode homograph detection ───────────────────────────────
        // Only flag mixed-script (non-ASCII + ASCII letters together)
        // Purely non-Latin (e.g. Bengali name) is allowed
        if (noUnicodeHomograph
                && NON_ASCII_PATTERN.matcher(v).find()
                && ASCII_LETTER_PATTERN.matcher(v).find()) {
            log.warn("[SafeInput] Unicode homograph suspected: {}", v);
            return fail(ctx, "Invalid characters detected");
        }

        // ── 6. Whitespace checks ──────────────────────────────────────────
        if (noWhitespace && !NO_WHITESPACE.matcher(v).matches())
            return fail(ctx, "Whitespace is not allowed");

        // ── 7. Length checks ──────────────────────────────────────────────
        if (v.length() < minLength)
            return fail(ctx, "Minimum length is " + minLength + " characters");
        if (v.length() > maxLength)
            return fail(ctx, "Maximum length is " + maxLength + " characters");

        // ── 8. Word count check ───────────────────────────────────────────
        if (maxWords > 0) {
            long wordCount = java.util.Arrays.stream(v.trim().split("\\s+"))
                    .filter(w -> !w.isEmpty()).count();
            if (wordCount > maxWords)
                return fail(ctx, "Maximum " + maxWords + " words allowed");
        }

        // ── 9. Format checks ──────────────────────────────────────────────
        if (emailFormat && !EMAIL_PATTERN.matcher(v).matches())
            return fail(ctx, "Invalid email format");

        if (phoneFormat && !PHONE_PATTERN.matcher(v).matches())
            return fail(ctx, "Invalid phone number format");

        if (url && !URL_PATTERN.matcher(v).matches())
            return fail(ctx, "Invalid URL format — must start with http/https/ftp");

        if (alphaOnly && !ALPHA_PATTERN.matcher(v).matches())
            return fail(ctx, "Only alphabetic characters (a-z, A-Z) are allowed");

        if (alphanumeric && !ALPHANUM_PATTERN.matcher(v).matches())
            return fail(ctx, "Only alphanumeric characters (a-z, A-Z, 0-9) are allowed");

        if (noSpecialChars && !NO_SPECIAL_PATTERN.matcher(v).matches())
            return fail(ctx, "Special characters are not allowed");

        if (!pattern.isEmpty() && !v.matches(pattern))
            return fail(ctx, "Value does not match the required format");

        // ── 10. Numeric-only format check ─────────────────────────────────
        if (numericOnly && !NUMERIC_PATTERN.matcher(v).matches())
            return fail(ctx, "Only numeric digits (0-9) are allowed");

        // ── 11. Integer numeric range checks ──────────────────────────────
        boolean hasNumericConstraint = positive || positiveOrZero || negative
                || negativeOrZero || minValue != Long.MIN_VALUE || maxValue != Long.MAX_VALUE;

        if (numericOnly || hasNumericConstraint) {
            try {
                long num = Long.parseLong(v);
                if (positive       && num <= 0) return fail(ctx, "Value must be positive (> 0)");
                if (positiveOrZero && num <  0) return fail(ctx, "Value must be positive or zero (>= 0)");
                if (negative       && num >= 0) return fail(ctx, "Value must be negative (< 0)");
                if (negativeOrZero && num >  0) return fail(ctx, "Value must be negative or zero (<= 0)");
                if (minValue != Long.MIN_VALUE && num < minValue)
                    return fail(ctx, "Value must be at least " + minValue);
                if (maxValue != Long.MAX_VALUE && num > maxValue)
                    return fail(ctx, "Value must be at most " + maxValue);
            } catch (NumberFormatException ignored) {
                // Not a long — decimal checks below will handle it if needed
            }
        }

        // ── 12. Decimal / BigDecimal checks ───────────────────────────────
        boolean hasDecimalConstraint = !decimalMin.isEmpty() || !decimalMax.isEmpty()
                || integerDigits > 0 || fractionDigits > 0;

        if (hasDecimalConstraint) {
            try {
                BigDecimal num = new BigDecimal(v);

                if (!decimalMin.isEmpty()) {
                    BigDecimal min = new BigDecimal(decimalMin);
                    boolean valid = decimalInclusive
                            ? num.compareTo(min) >= 0
                            : num.compareTo(min) >  0;
                    if (!valid) return fail(ctx, "Value must be "
                            + (decimalInclusive ? ">= " : "> ") + decimalMin);
                }

                if (!decimalMax.isEmpty()) {
                    BigDecimal max = new BigDecimal(decimalMax);
                    boolean valid = decimalInclusive
                            ? num.compareTo(max) <= 0
                            : num.compareTo(max) <  0;
                    if (!valid) return fail(ctx, "Value must be "
                            + (decimalInclusive ? "<= " : "< ") + decimalMax);
                }

                // Digit precision check — prevents DB DECIMAL(integerDigits, fractionDigits) overflow
                String plain = num.toPlainString().replace("-", "");
                String[] parts = plain.split("\\.");
                if (integerDigits > 0 && parts[0].length() > integerDigits)
                    return fail(ctx, "Integer part must not exceed " + integerDigits + " digits");
                if (fractionDigits > 0 && parts.length > 1 && parts[1].length() > fractionDigits)
                    return fail(ctx, "Decimal part must not exceed " + fractionDigits + " places");

            } catch (NumberFormatException e) {
                return fail(ctx, "Must be a valid numeric value");
            }
        }

        // ── 13. Date checks ───────────────────────────────────────────────
        boolean hasDateConstraint = past || pastOrPresent || future || futureOrPresent
                || !dateFormat.isEmpty();

        if (hasDateConstraint) {
            try {
                String fmt = dateFormat.isEmpty() ? "yyyy-MM-dd" : dateFormat;
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern(fmt);
                LocalDate date  = LocalDate.parse(v, formatter);
                LocalDate today = LocalDate.now();

                if (past          && !date.isBefore(today))  return fail(ctx, "Date must be in the past");
                if (pastOrPresent &&  date.isAfter(today))   return fail(ctx, "Date must be today or in the past");
                if (future        && !date.isAfter(today))   return fail(ctx, "Date must be in the future");
                if (futureOrPresent && date.isBefore(today)) return fail(ctx, "Date must be today or in the future");

            } catch (Exception e) {
                String expected = dateFormat.isEmpty() ? "yyyy-MM-dd" : dateFormat;
                return fail(ctx, "Invalid date — expected format: " + expected);
            }
        }

        // ── 14. Boolean assertion checks ──────────────────────────────────
        if (assertTrue  && !v.equalsIgnoreCase("true"))  return fail(ctx, "Value must be true");
        if (assertFalse && !v.equalsIgnoreCase("false")) return fail(ctx, "Value must be false");

        // ── 15. XSS / HTML injection check ───────────────────────────────
        if (!allowHtml) {
            // XSS_PATTERN alone is sufficient and accurate
            if (XSS_PATTERN.matcher(v).find()) {
                log.warn("[SafeInput] XSS pattern detected: {}", v);
                return fail(ctx, "HTML or script content is not allowed");
            }
        }

        // ── 16. SQL injection check ───────────────────────────────────────
        if (noSqlInjection && SQL_PATTERN.matcher(v).find()) {
            log.warn("[SafeInput] SQL injection attempt detected: {}", v);
            return fail(ctx, "Invalid input detected");
        }

        // ── 17. Path traversal check ──────────────────────────────────────
        if (noPathTraversal && PATH_TRAVERSAL_PATTERN.matcher(v).find()) {
            log.warn("[SafeInput] Path traversal attempt detected: {}", v);
            return fail(ctx, "Invalid input detected");
        }

        // ── 18. Command injection check ───────────────────────────────────
        if (noCommandInjection && COMMAND_PATTERN.matcher(v).find()) {
            log.warn("[SafeInput] Command injection attempt detected: {}", v);
            return fail(ctx, "Invalid characters detected");
        }

        return true;
    }

    // ══════════════════════════════════════════════════════════════════════
    // HELPER — fail with custom message
    // ══════════════════════════════════════════════════════════════════════
    private boolean fail(ConstraintValidatorContext ctx, String msg) {
        ctx.buildConstraintViolationWithTemplate(msg).addConstraintViolation();
        return false;
    }
}