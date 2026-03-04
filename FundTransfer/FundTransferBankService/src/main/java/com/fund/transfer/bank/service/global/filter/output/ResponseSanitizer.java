package com.fund.transfer.bank.service.global.filter.output;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

@Slf4j
@Component
public class ResponseSanitizer {

    private static final Pattern HTML_PATTERN = Pattern.compile(
            "<[^>]*script|javascript:|vbscript:|onload=|onerror=|onclick=|" +
                    "eval\\(|expression\\(|<[^>]+>",
            Pattern.CASE_INSENSITIVE
    );

    //  main method — always use this in controllers
    public <T> T sanitize(T object, String userRole) {
        if (object == null) return null;

        //  normalize role — null stays null (will be treated as most restrictive)
        String resolvedRole = (userRole != null && !userRole.isBlank())
                ? userRole.toUpperCase()
                : null;

        log.debug("Sanitizing {} for role: '{}'",
                object.getClass().getSimpleName(), resolvedRole);

        try {
            processFields(object, object.getClass(), resolvedRole);
        } catch (Exception e) {
            log.error("Sanitization failed — type: {}, role: {}",
                    object.getClass().getSimpleName(), resolvedRole, e);
        }
        return object;
    }

    //  no role = null = most restrictive
    public <T> T sanitize(T object) {
        return sanitize(object, null);
    }

    //  list sanitization with role
    public <T> List<T> sanitizeList(List<T> list, String userRole) {
        if (list == null || list.isEmpty()) return list;
        list.forEach(item -> sanitize(item, userRole));
        return list;
    }

    //  list sanitization without role
    public <T> List<T> sanitizeList(List<T> list) {
        return sanitizeList(list, null);
    }

    private void processFields(Object object, Class<?> clazz, String userRole)
            throws Exception {
        if (clazz == null || clazz == Object.class) return;

        for (Field field : clazz.getDeclaredFields()) {
            if (!field.isAnnotationPresent(SafeOutput.class)) continue;

            field.setAccessible(true);
            SafeOutput annotation = field.getAnnotation(SafeOutput.class);
            Object value = field.get(object);

            if (value == null) continue;

            boolean canSee = canRoleSeeFullData(userRole, annotation.visibleToRoles());
            log.debug("Field '{}' — role: '{}', canSee: {}",
                    field.getName(), userRole, canSee);

            // ── Hidden ──────────────────────────────────────────────────
            if (annotation.hidden()) {
                if (!canSee) {
                    field.set(object, null);
                    log.debug("Field '{}' hidden for role '{}'", field.getName(), userRole);
                }
                continue;
            }

            // ── Placeholder ─────────────────────────────────────────────
            if (!annotation.placeholder().isEmpty() && value instanceof String) {
                if (!canSee) {
                    field.set(object, annotation.placeholder());
                }
                continue;
            }

            // ── String processing ────────────────────────────────────────
            if (value instanceof String str) {

                //  sanitizeHtml ALWAYS runs — no role bypass
                if (annotation.sanitizeHtml()) {
                    str = sanitizeHtml(str);
                }

                // ── Masked ───────────────────────────────────────────────
                if (annotation.masked()) {
                    if (canSee) {
                        field.set(object, str);
                        log.debug("Field '{}' unmasked for role '{}'",
                                field.getName(), userRole);
                    } else {
                        field.set(object, mask(str, annotation.visibleChars()));
                        log.debug("Field '{}' masked for role '{}'",
                                field.getName(), userRole);
                    }
                    continue;
                }

                // ── Truncate ─────────────────────────────────────────────
                if (annotation.truncate()) {
                    if (canSee) {
                        field.set(object, str);
                    } else if (str.length() > annotation.maxLength()) {
                        field.set(object, str.substring(0, annotation.maxLength()) + "...");
                    } else {
                        field.set(object, str);
                    }
                    continue;
                }

                //  only sanitizeHtml was applied
                field.set(object, str);
            }
        }

        //  process parent class fields too
        processFields(object, clazz.getSuperclass(), userRole);
    }

    /**
     * null role  → ALWAYS false (most restrictive, no exceptions)
     * empty list → true (no restriction defined, authenticated users see full)
     * role in list → true
     * role not in list → false
     */
    private boolean canRoleSeeFullData(String userRole, String[] visibleToRoles) {
        //  null role = always restricted — comes first, no exceptions
        if (userRole == null) {
            return false;
        }
        //  empty list = no restriction defined = authenticated role sees full
        if (visibleToRoles == null || visibleToRoles.length == 0) {
            return true;
        }
        //  check if role is in allowed list
        return Arrays.asList(visibleToRoles).contains(userRole);
    }

    private String mask(String value, int visibleChars) {
        if (value.length() <= visibleChars) return "*".repeat(value.length());
        return "*".repeat(value.length() - visibleChars)
                + value.substring(value.length() - visibleChars);
    }

    private String sanitizeHtml(String value) {
        return HTML_PATTERN.matcher(value).replaceAll("");
    }
}