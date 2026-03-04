package com.fund.transfer.bank.service.global.filter.output;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface SafeOutput {

    /**
     * Completely hide this field from response — field becomes null.
     * WHY: Hide passwords, tokens, internal IDs, audit fields.
     * HOW:
     *   @SafeOutput(hidden = true)
     *   private String password; // → never appears in response
     */
    boolean hidden() default false;

    /**
     * Mask the value — show only last N characters.
     * WHY: Partially show account numbers, phone numbers for UI display.
     * HOW:
     *   @SafeOutput(masked = true, visibleChars = 4)
     *   private String accountNumber; // "1234567890" → "******7890"
     */
    boolean masked() default false;
    int visibleChars() default 4;

    /**
     * Truncate string to max length before sending.
     * WHY: Prevent oversized responses or accidental data dumps.
     * HOW:
     *   @SafeOutput(truncate = true, maxLength = 100)
     *   private String description; // truncates at 100 chars
     */
    boolean truncate() default false;
    int maxLength() default 255;

    /**
     * Sanitize HTML from output to prevent stored XSS.
     * WHY: If value came from user input and is being reflected back.
     * HOW:
     *   @SafeOutput(sanitizeHtml = true)
     *   private String bio; // strips <script> tags from stored value
     */
    boolean sanitizeHtml() default false;

    /**
     * Replace value with a fixed placeholder string.
     * WHY: Show that a field exists but hide its actual value.
     * HOW:
     *   @SafeOutput(placeholder = "********")
     *   private String secretKey; // → "********"
     */
    String placeholder() default "";
}