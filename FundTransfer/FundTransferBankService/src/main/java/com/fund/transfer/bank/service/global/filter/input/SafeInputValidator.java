package com.fund.transfer.bank.service.global.filter.input;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.regex.Pattern;

@Component
public class SafeInputValidator implements ConstraintValidator<SafeInput, String> {

    private static final Logger log = LoggerFactory.getLogger(SafeInputValidator.class);

    private static final Pattern XSS_PATTERN = Pattern.compile(
            "<[^>]*script|javascript:|vbscript:|onload=|onerror=|onclick=|" +
                    "eval\\(|expression\\(|document\\.|window\\.|alert\\(|confirm\\(|prompt\\(",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern SQL_PATTERN = Pattern.compile(
            "(?i)(select|insert|update|delete|drop|truncate|alter|exec|execute|" +
                    "union|fetch|declare|cast|convert|char|nchar|varchar|nvarchar|" +
                    "--|\\/\\*|\\*\\/|xp_|sp_|0x[0-9a-f]+)",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern PATH_TRAVERSAL_PATTERN = Pattern.compile(
            "\\.\\./|\\.\\.\\\\|%2e%2e%2f|%2e%2e/|\\.%2f|%2e\\./",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern COMMAND_INJECTION_PATTERN = Pattern.compile(
            "[;&|`$(){}\\[\\]]|\\|\\||&&",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$");

    private static final Pattern NUMERIC_PATTERN    = Pattern.compile("^[0-9]+$");
    private static final Pattern ALPHA_PATTERN      = Pattern.compile("^[a-zA-Z]+$");
    private static final Pattern ALPHANUM_PATTERN   = Pattern.compile("^[a-zA-Z0-9]+$");
    private static final Pattern NO_SPECIAL_PATTERN = Pattern.compile("^[a-zA-Z0-9\\s]+$");
    private static final Pattern NO_WHITESPACE      = Pattern.compile("^\\S+$");
    private static final Pattern URL_PATTERN        = Pattern.compile(
            "^(https?|ftp)://[^\\s/$.?#].[^\\s]*$", Pattern.CASE_INSENSITIVE);

    // annotation fields
    private boolean required, notNull, notEmpty;
    private int minLength, maxLength;
    private boolean numericOnly, positive, positiveOrZero, negative, negativeOrZero;
    private long minValue, maxValue;
    private int integerDigits, fractionDigits;
    private String decimalMin, decimalMax;
    private boolean decimalInclusive;
    private boolean emailFormat, url, alphanumeric, alphaOnly, noSpecialChars;
    private String pattern;
    private boolean past, pastOrPresent, future, futureOrPresent;
    private String dateFormat;
    private boolean assertTrue, assertFalse;
    private boolean allowHtml, noSqlInjection, noPathTraversal, noCommandInjection;
    private boolean trimmed, noWhitespace;

    @Override
    public void initialize(SafeInput a) {
        required            = a.required();
        notNull             = a.notNull();
        notEmpty            = a.notEmpty();
        minLength           = a.minLength();
        maxLength           = a.maxLength();
        numericOnly         = a.numericOnly();
        positive            = a.positive();
        positiveOrZero      = a.positiveOrZero();
        negative            = a.negative();
        negativeOrZero      = a.negativeOrZero();
        minValue            = a.minValue();
        maxValue            = a.maxValue();
        integerDigits       = a.integerDigits();
        fractionDigits      = a.fractionDigits();
        decimalMin          = a.decimalMin();
        decimalMax          = a.decimalMax();
        decimalInclusive    = a.decimalInclusive();
        emailFormat         = a.emailFormat();
        url                 = a.url();
        alphanumeric        = a.alphanumeric();
        alphaOnly           = a.alphaOnly();
        noSpecialChars      = a.noSpecialChars();
        pattern             = a.pattern();
        past                = a.past();
        pastOrPresent       = a.pastOrPresent();
        future              = a.future();
        futureOrPresent     = a.futureOrPresent();
        dateFormat          = a.dateFormat();
        assertTrue          = a.assertTrue();
        assertFalse         = a.assertFalse();
        allowHtml           = a.allowHtml();
        noSqlInjection      = a.noSqlInjection();
        noPathTraversal     = a.noPathTraversal();
        noCommandInjection  = a.noCommandInjection();
        trimmed             = a.trimmed();
        noWhitespace        = a.noWhitespace();
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext ctx) {
        ctx.disableDefaultConstraintViolation();

        // ── Null checks ──────────────────────────────────────────────────────
        if (value == null) {
            if (required || notNull || notEmpty) {
                return fail(ctx, "This field is required");
            }
            return true;
        }

        String v = trimmed ? value.trim() : value;

        // ── Empty checks ─────────────────────────────────────────────────────
        if (v.isBlank()) {
            if (required || notEmpty) return fail(ctx, "This field must not be empty");
            return true;
        }

        // ── Whitespace ───────────────────────────────────────────────────────
        if (noWhitespace && !NO_WHITESPACE.matcher(v).matches())
            return fail(ctx, "No whitespace allowed");

        // ── Length ───────────────────────────────────────────────────────────
        if (v.length() < minLength)
            return fail(ctx, "Minimum length is " + minLength);
        if (v.length() > maxLength)
            return fail(ctx, "Maximum length is " + maxLength);

        // ── Format ───────────────────────────────────────────────────────────
        if (emailFormat && !EMAIL_PATTERN.matcher(v).matches())
            return fail(ctx, "Invalid email format");

        if (url && !URL_PATTERN.matcher(v).matches())
            return fail(ctx, "Invalid URL format");

        if (alphaOnly && !ALPHA_PATTERN.matcher(v).matches())
            return fail(ctx, "Only alphabetic characters allowed");

        if (alphanumeric && !ALPHANUM_PATTERN.matcher(v).matches())
            return fail(ctx, "Only alphanumeric characters allowed");

        if (noSpecialChars && !NO_SPECIAL_PATTERN.matcher(v).matches())
            return fail(ctx, "Special characters are not allowed");

        if (!pattern.isEmpty() && !v.matches(pattern))
            return fail(ctx, "Value does not match required pattern");

        // ── Numeric ──────────────────────────────────────────────────────────
        if (numericOnly && !NUMERIC_PATTERN.matcher(v).matches())
            return fail(ctx, "Only numeric values allowed");

        if (positive || positiveOrZero || negative || negativeOrZero ||
                minValue != Long.MIN_VALUE || maxValue != Long.MAX_VALUE) {
            try {
                long num = Long.parseLong(v);
                if (positive && num <= 0)
                    return fail(ctx, "Value must be positive");
                if (positiveOrZero && num < 0)
                    return fail(ctx, "Value must be positive or zero");
                if (negative && num >= 0)
                    return fail(ctx, "Value must be negative");
                if (negativeOrZero && num > 0)
                    return fail(ctx, "Value must be negative or zero");
                if (minValue != Long.MIN_VALUE && num < minValue)
                    return fail(ctx, "Value must be at least " + minValue);
                if (maxValue != Long.MAX_VALUE && num > maxValue)
                    return fail(ctx, "Value must be at most " + maxValue);
            } catch (NumberFormatException ignored) {
                // not numeric — skip numeric checks
            }
        }

        // ── Decimal ──────────────────────────────────────────────────────────
        if (!decimalMin.isEmpty() || !decimalMax.isEmpty()) {
            try {
                BigDecimal num = new BigDecimal(v);
                if (!decimalMin.isEmpty()) {
                    BigDecimal min = new BigDecimal(decimalMin);
                    boolean valid = decimalInclusive ? num.compareTo(min) >= 0 : num.compareTo(min) > 0;
                    if (!valid) return fail(ctx, "Value must be " + (decimalInclusive ? ">= " : "> ") + decimalMin);
                }
                if (!decimalMax.isEmpty()) {
                    BigDecimal max = new BigDecimal(decimalMax);
                    boolean valid = decimalInclusive ? num.compareTo(max) <= 0 : num.compareTo(max) < 0;
                    if (!valid) return fail(ctx, "Value must be " + (decimalInclusive ? "<= " : "< ") + decimalMax);
                }
            } catch (NumberFormatException ignored) {}
        }

        // ── Digits ───────────────────────────────────────────────────────────
        if (integerDigits > 0 || fractionDigits > 0) {
            try {
                BigDecimal num = new BigDecimal(v);
                String[] parts = v.replace("-", "").split("\\.");
                if (integerDigits > 0 && parts[0].length() > integerDigits)
                    return fail(ctx, "Integer part must not exceed " + integerDigits + " digits");
                if (fractionDigits > 0 && parts.length > 1 && parts[1].length() > fractionDigits)
                    return fail(ctx, "Fraction part must not exceed " + fractionDigits + " digits");
            } catch (NumberFormatException ignored) {}
        }

        // ── Date ─────────────────────────────────────────────────────────────
        if (!dateFormat.isEmpty() || past || pastOrPresent || future || futureOrPresent) {
            try {
                String fmt = dateFormat.isEmpty() ? "yyyy-MM-dd" : dateFormat;
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern(fmt);
                LocalDate date = LocalDate.parse(v, formatter);
                LocalDate today = LocalDate.now();
                if (past && !date.isBefore(today))
                    return fail(ctx, "Date must be in the past");
                if (pastOrPresent && date.isAfter(today))
                    return fail(ctx, "Date must be in the past or present");
                if (future && !date.isAfter(today))
                    return fail(ctx, "Date must be in the future");
                if (futureOrPresent && date.isBefore(today))
                    return fail(ctx, "Date must be in the future or present");
            } catch (Exception e) {
                return fail(ctx, "Invalid date format, expected: " + (dateFormat.isEmpty() ? "yyyy-MM-dd" : dateFormat));
            }
        }

        // ── Security ─────────────────────────────────────────────────────────
        if (!allowHtml && XSS_PATTERN.matcher(v).find()) {
            log.warn("XSS attempt: {}", v);
            return fail(ctx, "Invalid characters detected");
        }
        if (noSqlInjection && SQL_PATTERN.matcher(v).find()) {
            log.warn("SQL injection attempt: {}", v);
            return fail(ctx, "Invalid input detected");
        }
        if (noPathTraversal && PATH_TRAVERSAL_PATTERN.matcher(v).find()) {
            log.warn("Path traversal attempt: {}", v);
            return fail(ctx, "Invalid input detected");
        }
        if (noCommandInjection && COMMAND_INJECTION_PATTERN.matcher(v).find()) {
            log.warn("Command injection attempt: {}", v);
            return fail(ctx, "Invalid characters detected");
        }

        return true;
    }

    private boolean fail(ConstraintValidatorContext ctx, String message) {
        ctx.buildConstraintViolationWithTemplate(message).addConstraintViolation();
        return false;
    }
}