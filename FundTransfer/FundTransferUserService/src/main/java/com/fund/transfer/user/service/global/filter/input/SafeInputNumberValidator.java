package com.fund.transfer.user.service.global.filter.input;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;

/**
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║                  SafeInputNumberValidator (Number)                       ║
 * ╠══════════════════════════════════════════════════════════════════════════╣
 * ║ Validates Number fields (Integer, Long, Double, BigDecimal, Float)       ║
 * ║ annotated with @SafeInput.                                               ║
 * ║                                                                          ║
 * ║ Improvements over v1:                                                    ║
 * ║  + decimalMin / decimalMax support                                       ║
 * ║  + integerDigits / fractionDigits precision check                        ║
 * ║    → prevents DB DECIMAL(18,2) column overflow                           ║
 * ║  + decimalInclusive boundary control                                     ║
 * ║  + minValue / maxValue via BigDecimal (not just long comparison)         ║
 * ║  + Detailed fail messages per constraint                                 ║
 * ║                                                                          ║
 * ║ Works alongside SafeInputValidator:                                      ║
 * ║   SafeInputValidator       → handles String fields                       ║
 * ║   SafeInputNumberValidator → handles Number fields (this class)          ║
 * ║                                                                          ║
 * ║ Supports all Number subtypes:                                            ║
 * ║   Integer, Long, Short, Byte, Double, Float, BigDecimal, BigInteger      ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */
@Component
public class SafeInputNumberValidator implements ConstraintValidator<SafeInput, Number> {

    private static final Logger log = LoggerFactory.getLogger(SafeInputNumberValidator.class);

    // ══════════════════════════════════════════════════════════════════════
    // ANNOTATION FIELDS — populated in initialize()
    // ══════════════════════════════════════════════════════════════════════
    private boolean required;
    private boolean notNull;
    private boolean positive;
    private boolean positiveOrZero;
    private boolean negative;
    private boolean negativeOrZero;
    private long    minValue;
    private long    maxValue;
    private String  decimalMin;
    private String  decimalMax;
    private boolean decimalInclusive;
    private int     integerDigits;
    private int     fractionDigits;

    // ══════════════════════════════════════════════════════════════════════
    // INITIALIZE — called once per annotated field at startup
    // ══════════════════════════════════════════════════════════════════════
    @Override
    public void initialize(SafeInput a) {
        required         = a.required();
        notNull          = a.notNull();
        positive         = a.positive();
        positiveOrZero   = a.positiveOrZero();
        negative         = a.negative();
        negativeOrZero   = a.negativeOrZero();
        minValue         = a.minValue();
        maxValue         = a.maxValue();
        decimalMin       = a.decimalMin();
        decimalMax       = a.decimalMax();
        decimalInclusive = a.decimalInclusive();
        integerDigits    = a.integerDigits();
        fractionDigits   = a.fractionDigits();
    }

    // ══════════════════════════════════════════════════════════════════════
    // IS VALID — main validation entry point
    // ══════════════════════════════════════════════════════════════════════
    @Override
    public boolean isValid(Number value, ConstraintValidatorContext ctx) {
        ctx.disableDefaultConstraintViolation();

        // ── 1. Null check ─────────────────────────────────────────────────
        if (value == null) {
            if (required || notNull)
                return fail(ctx, "Value is required");
            return true; // null is acceptable for optional numeric fields
        }

        // ── 2. Convert to BigDecimal ──────────────────────────────────────
        // BigDecimal is used for ALL comparisons because:
        //   - Double/Float have precision loss (0.1 + 0.2 ≠ 0.3)
        //   - BigDecimal preserves exact decimal representation
        //   - Works for Integer, Long, Double, BigDecimal, Float all at once
        BigDecimal num;
        try {
            num = new BigDecimal(value.toString());
        } catch (NumberFormatException e) {
            log.warn("[SafeInputNumber] Could not parse number: {}", value);
            return fail(ctx, "Invalid numeric value");
        }

        // ── 3. Sign checks ────────────────────────────────────────────────
        // positive       → must be > 0  (e.g. transfer amount, price)
        // positiveOrZero → must be >= 0 (e.g. balance, quantity)
        // negative       → must be < 0  (e.g. debit recorded as negative)
        // negativeOrZero → must be <= 0 (e.g. adjustment, discount)
        if (positive && num.compareTo(BigDecimal.ZERO) <= 0)
            return fail(ctx, "Value must be positive (> 0)");

        if (positiveOrZero && num.compareTo(BigDecimal.ZERO) < 0)
            return fail(ctx, "Value must be positive or zero (>= 0)");

        if (negative && num.compareTo(BigDecimal.ZERO) >= 0)
            return fail(ctx, "Value must be negative (< 0)");

        if (negativeOrZero && num.compareTo(BigDecimal.ZERO) > 0)
            return fail(ctx, "Value must be negative or zero (<= 0)");

        // ── 4. Long min/max range checks ──────────────────────────────────
        // minValue/maxValue are long — convert to BigDecimal for safe comparison
        // Example: @SafeInput(minValue = 1, maxValue = 1000000)
        if (minValue != Long.MIN_VALUE) {
            if (num.compareTo(BigDecimal.valueOf(minValue)) < 0)
                return fail(ctx, "Value must be at least " + minValue);
        }
        if (maxValue != Long.MAX_VALUE) {
            if (num.compareTo(BigDecimal.valueOf(maxValue)) > 0)
                return fail(ctx, "Value must be at most " + maxValue);
        }

        // ── 5. Decimal min/max checks ─────────────────────────────────────
        // More precise than minValue/maxValue — supports decimal boundaries
        // Example: @SafeInput(decimalMin = "0.01", decimalMax = "999999.99")
        if (!decimalMin.isEmpty()) {
            try {
                BigDecimal min   = new BigDecimal(decimalMin);
                boolean    valid = decimalInclusive
                        ? num.compareTo(min) >= 0    // >= min (inclusive)
                        : num.compareTo(min) >  0;   // >  min (exclusive)
                if (!valid)
                    return fail(ctx, "Value must be "
                            + (decimalInclusive ? ">= " : "> ") + decimalMin);
            } catch (NumberFormatException e) {
                log.error("[SafeInputNumber] Invalid decimalMin config: {}", decimalMin);
            }
        }

        if (!decimalMax.isEmpty()) {
            try {
                BigDecimal max   = new BigDecimal(decimalMax);
                boolean    valid = decimalInclusive
                        ? num.compareTo(max) <= 0    // <= max (inclusive)
                        : num.compareTo(max) <  0;   // <  max (exclusive)
                if (!valid)
                    return fail(ctx, "Value must be "
                            + (decimalInclusive ? "<= " : "< ") + decimalMax);
            } catch (NumberFormatException e) {
                log.error("[SafeInputNumber] Invalid decimalMax config: {}", decimalMax);
            }
        }

        // ── 6. Decimal precision check ────────────────────────────────────
        // WHY THIS IS CRITICAL:
        //   DB column: DECIMAL(18, 2) → max 18 total digits, 2 after decimal
        //   Without this check, someone could submit:
        //     balance = 9999999999999999.9999  → overflows DB column → exception
        //     amount  = 0.000001               → fractionDigits=2 → rounds silently
        //
        // integerDigits  → max digits BEFORE decimal point
        // fractionDigits → max digits AFTER  decimal point
        //
        // Example:
        //   @SafeInput(integerDigits = 16, fractionDigits = 2)
        //   private BigDecimal amount;
        //   → "1234567890123456.99" passes (16 int, 2 frac)
        //   → "12345678901234567.99" fails (17 int digits > 16)
        //   → "100.999" fails (3 frac digits > 2)
        if (integerDigits > 0 || fractionDigits > 0) {
            // toPlainString() avoids scientific notation (1.23E+10 → 12300000000)
            // remove minus sign so negative numbers are measured correctly
            String plain = num.toPlainString().replace("-", "");
            String[] parts = plain.split("\\.");

            String intPart  = parts[0];
            String fracPart = parts.length > 1 ? parts[1] : "";

            if (integerDigits > 0 && intPart.length() > integerDigits) {
                return fail(ctx, "Integer part must not exceed " + integerDigits
                        + " digits (got " + intPart.length() + ")");
            }

            if (fractionDigits > 0 && fracPart.length() > fractionDigits) {
                return fail(ctx, "Decimal places must not exceed " + fractionDigits
                        + " digits (got " + fracPart.length() + ")");
            }

            // No fraction digits allowed but value has them
            if (fractionDigits == 0 && !fracPart.isEmpty()) {
                return fail(ctx, "Decimal values are not allowed for this field");
            }
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