package com.fund.transfer.bank.service.global.filter.input;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.stereotype.Component;

@Component
public class SafeInputNumberValidator implements ConstraintValidator<SafeInput, Number> {

    private boolean positiveOrZero;
    private boolean positive;
    private boolean negativeOrZero;
    private boolean negative;
    private long minValue;
    private long maxValue;

    @Override
    public void initialize(SafeInput a) {
        positiveOrZero = a.positiveOrZero();
        positive       = a.positive();
        negativeOrZero = a.negativeOrZero();
        negative       = a.negative();
        minValue       = a.minValue();
        maxValue       = a.maxValue();
    }

    @Override
    public boolean isValid(Number value, ConstraintValidatorContext ctx) {
        if (value == null) return true;

        ctx.disableDefaultConstraintViolation();
        long v = value.longValue();

        if (positive && v <= 0)
            return fail(ctx, "Value must be positive");
        if (positiveOrZero && v < 0)
            return fail(ctx, "Value must be positive or zero");
        if (negative && v >= 0)
            return fail(ctx, "Value must be negative");
        if (negativeOrZero && v > 0)
            return fail(ctx, "Value must be negative or zero");
        if (minValue != Long.MIN_VALUE && v < minValue)
            return fail(ctx, "Value must be at least " + minValue);
        if (maxValue != Long.MAX_VALUE && v > maxValue)
            return fail(ctx, "Value must be at most " + maxValue);

        return true;
    }

    private boolean fail(ConstraintValidatorContext ctx, String msg) {
        ctx.buildConstraintViolationWithTemplate(msg).addConstraintViolation();
        return false;
    }
}