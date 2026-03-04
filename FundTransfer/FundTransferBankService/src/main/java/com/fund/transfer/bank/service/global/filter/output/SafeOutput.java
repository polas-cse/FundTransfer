package com.fund.transfer.bank.service.global.filter.output;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface SafeOutput {

    boolean hidden() default false;
    boolean masked() default false;
    int visibleChars() default 4;
    boolean truncate() default false;
    int maxLength() default 255;
    boolean sanitizeHtml() default false;
    String placeholder() default "";

    /**
     * Define WHICH roles can see full data.
     * Everyone NOT in this list gets masked/hidden.
     * null role is ALWAYS masked regardless.
     *
     * EXAMPLE 1:
     *   @SafeOutput(masked = true, visibleChars = 4, visibleToRoles = {"ADMIN", "SUPER_ADMIN"})
     *   private String accountNumber;
     *   null role   → "************3456"  ← always masked
     *   USER        → "************3456"  ← masked
     *   ADMIN       → "1234567890123456"  ← full
     *   SUPER_ADMIN → "1234567890123456"  ← full
     *
     * EXAMPLE 2:
     *   @SafeOutput(hidden = true, visibleToRoles = {"SUPER_ADMIN"})
     *   private Long userId;
     *   null role   → null    ← always hidden
     *   USER        → null    ← hidden
     *   ADMIN       → null    ← hidden
     *   SUPER_ADMIN → 1001    ← visible
     *
     * EXAMPLE 3:
     *   @SafeOutput(masked = true, visibleChars = 4)  ← empty visibleToRoles
     *   private String phone;
     *   null role   → masked  ← null is always masked
     *   USER        → full
     *   ADMIN       → full
     *   SUPER_ADMIN → full
     *
     * NOTE: sanitizeHtml always applies — cannot be bypassed by any role.
     */
    String[] visibleToRoles() default {};
}