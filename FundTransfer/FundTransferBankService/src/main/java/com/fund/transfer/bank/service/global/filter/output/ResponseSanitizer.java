package com.fund.transfer.bank.service.global.filter.output;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;
import java.util.List;
import java.util.regex.Pattern;

@Component
@Slf4j
public class ResponseSanitizer {

    private static final Pattern HTML_PATTERN = Pattern.compile(
            "<[^>]*script|javascript:|vbscript:|onload=|onerror=|onclick=|" +
                    "eval\\(|expression\\(|<[^>]+>",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Sanitize any response object recursively.
     * Processes all fields annotated with @SafeOutput.
     */
    public <T> T sanitize(T object) {
        if (object == null) return null;

        try {
            processFields(object, object.getClass());
        } catch (Exception e) {
            log.error("Response sanitization failed for type: {}", object.getClass().getSimpleName(), e);
        }
        return object;
    }

    /**
     * Sanitize a list of response objects.
     */
    public <T> List<T> sanitizeList(List<T> list) {
        if (list == null || list.isEmpty()) return list;
        list.forEach(this::sanitize);
        return list;
    }

    private void processFields(Object object, Class<?> clazz) throws Exception {
        if (clazz == null || clazz == Object.class) return;

        for (Field field : clazz.getDeclaredFields()) {
            if (!field.isAnnotationPresent(SafeOutput.class)) continue;

            field.setAccessible(true);
            SafeOutput annotation = field.getAnnotation(SafeOutput.class);
            Object value = field.get(object);

            if (value == null) continue;

            // ── Hidden — set to null ─────────────────────────────────────
            if (annotation.hidden()) {
                field.set(object, null);
                continue;
            }

            // ── Placeholder — replace with fixed string ──────────────────
            if (!annotation.placeholder().isEmpty() && value instanceof String) {
                field.set(object, annotation.placeholder());
                continue;
            }

            // ── String-specific processing ───────────────────────────────
            if (value instanceof String str) {

                // Mask — show only last N chars
                if (annotation.masked()) {
                    field.set(object, mask(str, annotation.visibleChars()));
                    continue;
                }

                // Sanitize HTML — strip dangerous tags
                if (annotation.sanitizeHtml()) {
                    str = sanitizeHtml(str);
                }

                // Truncate — cut to max length
                if (annotation.truncate() && str.length() > annotation.maxLength()) {
                    str = str.substring(0, annotation.maxLength()) + "...";
                }

                field.set(object, str);
            }
        }

        //  Process parent class fields too
        processFields(object, clazz.getSuperclass());
    }

    private String mask(String value, int visibleChars) {
        if (value.length() <= visibleChars) return "*".repeat(value.length());
        String visible = value.substring(value.length() - visibleChars);
        String masked = "*".repeat(value.length() - visibleChars);
        return masked + visible;
    }

    private String sanitizeHtml(String value) {
        return HTML_PATTERN.matcher(value).replaceAll("");
    }
}