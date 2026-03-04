package com.fund.transfer.user.service.global.filter.input;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║                         @SafeInput Annotation                           ║
 * ╠══════════════════════════════════════════════════════════════════════════╣
 * ║ A centralized, all-in-one field validator that combines:                ║
 * ║  • Standard Bean Validation (NotNull, Size, Min, Max, Email, etc.)      ║
 * ║  • Security protection (XSS, SQL Injection, Path Traversal, etc.)       ║
 * ║  • Format validation (email, URL, regex, alphanumeric, etc.)            ║
 * ║  • Numeric, decimal, and date constraints                               ║
 * ╠══════════════════════════════════════════════════════════════════════════╣
 * ║ USAGE EXAMPLE:                                                          ║
 * ║                                                                         ║
 * ║  @SafeInput(required = true, minLength = 3, maxLength = 50)             ║
 * ║  private String userName;                                               ║
 * ║                                                                         ║
 * ║  @SafeInput(required = true, emailFormat = true, maxLength = 100)       ║
 * ║  private String email;                                                  ║
 * ║                                                                         ║
 * ║  @SafeInput(minValue = 1, maxValue = 100)                               ║
 * ║  private String age;                                                    ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = SafeInputValidator.class)
public @interface SafeInput {

    // ══════════════════════════════════════════════════════════════════════
    // DEFAULT BEAN VALIDATION — Required by Jakarta Validation specification
    // These 3 fields MUST exist in every custom constraint annotation
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Default error message returned when validation fails.
     * Can be overridden per field:
     *   @SafeInput(required = true, message = "Username is required")
     */
    String message() default "Invalid or potentially dangerous input detected";

    /**
     * Validation groups — allows conditional validation.
     * WHY: Run different validations for save vs update operations.
     * HOW:
     *   interface OnSave {}
     *   interface OnUpdate {}
     *   @SafeInput(required = true, groups = OnSave.class)
     *   @Validated(OnSave.class) on controller method
     */
    Class<?>[] groups() default {};

    /**
     * Payload — attach metadata to constraint for processing by clients.
     * WHY: Severity classification (e.g. ERROR vs WARNING level).
     * HOW:
     *   class Severity { interface Error extends Payload {} }
     *   @SafeInput(payload = Severity.Error.class)
     */
    Class<? extends Payload>[] payload() default {};


    // ══════════════════════════════════════════════════════════════════════
    // NULL / BLANK / EMPTY CHECKS
    // Controls whether the field can be missing, empty, or blank
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Equivalent to @NotBlank — field must not be null, empty, or whitespace-only.
     * WHY: Use for mandatory fields that must have a meaningful value.
     * HOW:
     *   @SafeInput(required = true)
     *   private String firstName; //  null, "", "   " all fail
     */
    boolean required() default false;

    /**
     * Equivalent to @NotNull — field must not be null but CAN be empty string.
     * WHY: Use when empty string is valid but null is not (e.g. optional text fields).
     * HOW:
     *   @SafeInput(notNull = true)
     *   private String middleName; //  "" is ok,  null fails
     */
    boolean notNull() default false;

    /**
     * Equivalent to @NotEmpty — field must not be null or empty string "".
     * WHY: Use when you want to reject empty strings but allow whitespace strings.
     * HOW:
     *   @SafeInput(notEmpty = true)
     *   private String code; //  "  " ok,  "" and null fail
     */
    boolean notEmpty() default false;


    // ══════════════════════════════════════════════════════════════════════
    // LENGTH / SIZE CONSTRAINTS
    // Controls the minimum and maximum character length of a string
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Equivalent to @Size(min = N) — minimum number of characters required.
     * WHY: Prevent too-short inputs like single-character names or weak passwords.
     * HOW:
     *   @SafeInput(required = true, minLength = 8)
     *   private String password; //  "abc" fails,  "password1" passes
     */
    int minLength() default 0;

    /**
     * Equivalent to @Size(max = N) — maximum number of characters allowed.
     * WHY: Prevent database overflow and buffer overrun attacks.
     * HOW:
     *   @SafeInput(maxLength = 50)
     *   private String userName; //  51+ chars fail,  50 chars or less pass
     */
    int maxLength() default 255;


    // ══════════════════════════════════════════════════════════════════════
    // NUMERIC CONSTRAINTS
    // Controls numeric validation for string fields that hold numeric values
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Only allows digit characters (0-9), no decimals or signs.
     * WHY: Validate phone numbers, OTP codes, or ID numbers.
     * HOW:
     *   @SafeInput(numericOnly = true, minLength = 10, maxLength = 15)
     *   private String phone; //  "01712345678",  "017-123" fails
     */
    boolean numericOnly() default false;

    /**
     * Equivalent to @Min — minimum numeric value (for numeric string fields).
     * WHY: Validate age ranges, quantities, or IDs must be above a threshold.
     * HOW:
     *   @SafeInput(minValue = 18, maxValue = 100)
     *   private String age; //  "17" fails,  "25" passes
     */
    long minValue() default Long.MIN_VALUE;

    /**
     * Equivalent to @Max — maximum numeric value (for numeric string fields).
     * WHY: Prevent unrealistically large numbers being submitted.
     * HOW:
     *   @SafeInput(maxValue = 999)
     *   private String quantity; //  "1000" fails,  "999" passes
     */
    long maxValue() default Long.MAX_VALUE;

    /**
     * Equivalent to @Positive — value must be strictly greater than 0.
     * WHY: Validate prices, counts, or IDs that must be positive.
     * HOW:
     *   @SafeInput(positive = true)
     *   private String price; //  "0", "-5" fail,  "1" passes
     */
    boolean positive() default false;

    /**
     * Equivalent to @PositiveOrZero — value must be >= 0.
     * WHY: Validate balances or scores that can be zero but not negative.
     * HOW:
     *   @SafeInput(positiveOrZero = true)
     *   private String balance; //  "-1" fails,  "0", "100" pass
     */
    boolean positiveOrZero() default false;

    /**
     * Equivalent to @Negative — value must be strictly less than 0.
     * WHY: Validate debit/withdrawal amounts stored as negative numbers.
     * HOW:
     *   @SafeInput(negative = true)
     *   private String debit; //  "0", "5" fail,  "-10" passes
     */
    boolean negative() default false;

    /**
     * Equivalent to @NegativeOrZero — value must be <= 0.
     * WHY: Validate adjustments or offsets that cannot be positive.
     * HOW:
     *   @SafeInput(negativeOrZero = true)
     *   private String adjustment; //  "1" fails,  "0", "-5" pass
     */
    boolean negativeOrZero() default false;

    /**
     * Equivalent to @Digits(integer = N) — max digits before decimal point.
     * WHY: Prevent invalid account numbers or amounts with too many digits.
     * HOW:
     *   @SafeInput(integerDigits = 5, fractionDigits = 2)
     *   private String amount; //  "123.45",  "1234567.89" fails
     */
    int integerDigits() default 0;

    /**
     * Equivalent to @Digits(fraction = N) — max digits after decimal point.
     * WHY: Enforce currency precision (e.g. max 2 decimal places).
     * HOW:
     *   @SafeInput(integerDigits = 10, fractionDigits = 2)
     *   private String price; //  "99.99",  "99.999" fails
     */
    int fractionDigits() default 0;

    /**
     * Equivalent to @DecimalMin — minimum decimal value as string.
     * WHY: Validate minimum transaction amounts or percentages.
     * HOW:
     *   @SafeInput(decimalMin = "0.01", decimalInclusive = true)
     *   private String amount; //  "0.00" fails,  "0.01" passes
     */
    String decimalMin() default "";

    /**
     * Equivalent to @DecimalMax — maximum decimal value as string.
     * WHY: Cap transfer amounts or limit percentage values.
     * HOW:
     *   @SafeInput(decimalMax = "999999.99")
     *   private String amount; //  "1000000.00" fails
     */
    String decimalMax() default "";

    /**
     * Whether decimalMin/decimalMax boundaries are inclusive.
     * WHY: Control if the boundary value itself is valid or not.
     * HOW:
     *   decimalInclusive = true  → value >= decimalMin (default)
     *   decimalInclusive = false → value > decimalMin (strict)
     */
    boolean decimalInclusive() default true;


    // ══════════════════════════════════════════════════════════════════════
    // FORMAT VALIDATORS
    // Controls the expected format/pattern of the string value
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Equivalent to @Email — validates proper email address format.
     * WHY: Ensure emails are structurally valid before saving or sending.
     * HOW:
     *   @SafeInput(required = true, emailFormat = true, maxLength = 100)
     *   private String email; //  "user@gmail.com",  "notanemail" fails
     */
    boolean emailFormat() default false;

    /**
     * Equivalent to @Pattern — validates against a custom regular expression.
     * WHY: Enforce specific formats like postal codes, national IDs, etc.
     * HOW:
     *   @SafeInput(pattern = "^[A-Z]{2}[0-9]{4}$")
     *   private String code; //  "AB1234",  "ab1234" fails
     */
    String pattern() default "";

    /**
     * Validates that the value is a valid URL (http/https/ftp).
     * WHY: Validate image URLs, download links, or webhook endpoints.
     * HOW:
     *   @SafeInput(url = true, maxLength = 500)
     *   private String imageUrl; //  "https://cdn.example.com/img.jpg"
     */
    boolean url() default false;

    /**
     * Only allows letters (a-z, A-Z) and digits (0-9), no special chars.
     * WHY: Validate usernames, reference codes, or slugs.
     * HOW:
     *   @SafeInput(alphanumeric = true, maxLength = 20)
     *   private String userName; //  "JohnDoe99",  "John_Doe" fails
     */
    boolean alphanumeric() default false;

    /**
     * Only allows alphabetic characters (a-z, A-Z), no digits or symbols.
     * WHY: Validate names that should contain only letters.
     * HOW:
     *   @SafeInput(alphaOnly = true, maxLength = 50)
     *   private String firstName; //  "John",  "John1" fails
     */
    boolean alphaOnly() default false;

    /**
     * Disallows special characters — only letters, digits, and spaces allowed.
     * WHY: Prevent injection via special characters in general text fields.
     * HOW:
     *   @SafeInput(noSpecialChars = true)
     *   private String description; //  "Hello!" fails,  "Hello World" passes
     */
    boolean noSpecialChars() default false;


    // ══════════════════════════════════════════════════════════════════════
    // DATE CONSTRAINTS
    // Controls date validation for string fields holding date values
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Equivalent to @Past — date must be before today.
     * WHY: Validate date of birth or historical event dates.
     * HOW:
     *   @SafeInput(past = true, dateFormat = "yyyy-MM-dd")
     *   private String dateOfBirth; //  future date fails,  "1990-01-01" passes
     */
    boolean past() default false;

    /**
     * Equivalent to @PastOrPresent — date must be today or earlier.
     * WHY: Validate transaction dates or activation dates.
     * HOW:
     *   @SafeInput(pastOrPresent = true)
     *   private String activationDate; //  tomorrow's date fails
     */
    boolean pastOrPresent() default false;

    /**
     * Equivalent to @Future — date must be after today.
     * WHY: Validate expiry dates, scheduled events, or card expiration.
     * HOW:
     *   @SafeInput(future = true)
     *   private String expiryDate; //  past date fails,  "2030-01-01" passes
     */
    boolean future() default false;

    /**
     * Equivalent to @FutureOrPresent — date must be today or later.
     * WHY: Validate scheduled payment dates or booking dates.
     * HOW:
     *   @SafeInput(futureOrPresent = true)
     *   private String scheduledDate; //  yesterday fails,  today or future passes
     */
    boolean futureOrPresent() default false;

    /**
     * Expected date format for parsing string date values.
     * WHY: Tell the validator how to parse the date string before checking constraints.
     * HOW:
     *   @SafeInput(past = true, dateFormat = "dd/MM/yyyy")
     *   private String dob; //  "25/12/1990",  "1990-12-25" fails (wrong format)
     * DEFAULT: "yyyy-MM-dd" if not specified
     */
    String dateFormat() default "";


    // ══════════════════════════════════════════════════════════════════════
    // BOOLEAN CONSTRAINTS
    // Controls boolean-like string validation
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Equivalent to @AssertTrue — value must equal "true" (case-insensitive).
     * WHY: Validate that terms & conditions or consent checkboxes are accepted.
     * HOW:
     *   @SafeInput(assertTrue = true)
     *   private String termsAccepted; //  "false" fails,  "true" passes
     */
    boolean assertTrue() default false;

    /**
     * Equivalent to @AssertFalse — value must equal "false" (case-insensitive).
     * WHY: Validate that a flag is explicitly set to false (e.g. accountLocked).
     * HOW:
     *   @SafeInput(assertFalse = true)
     *   private String accountLocked; //  "true" fails,  "false" passes
     */
    boolean assertFalse() default false;


    // ══════════════════════════════════════════════════════════════════════
    // SECURITY / SANITIZATION
    // Protects against common web application attacks
    // All security checks are ENABLED by default for maximum protection
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Allow or block HTML tags and JavaScript in input (XSS protection).
     * WHY: Prevent Cross-Site Scripting attacks via <script>, onerror=, etc.
     * HOW:
     *   @SafeInput(allowHtml = false)  // default — blocks <script>alert(1)</script>
     *   @SafeInput(allowHtml = true)   // only for rich text editor fields
     *   private String bio;
     */
    boolean allowHtml() default false;

    /**
     * Block SQL injection patterns (SELECT, DROP, UNION, --, etc.).
     * WHY: Prevent database destruction or data extraction via input fields.
     * HOW:
     *   @SafeInput(noSqlInjection = true) // default — blocks "1' OR '1'='1"
     *   private String search;
     * DISABLE ONLY IF: field will never reach a database query directly.
     */
    boolean noSqlInjection() default true;

    /**
     * Block path traversal patterns (../, ..\, %2e%2e%2f, etc.).
     * WHY: Prevent attackers from accessing files outside intended directories.
     * HOW:
     *   @SafeInput(noPathTraversal = true) // default — blocks "../../etc/passwd"
     *   private String filePath;
     * DISABLE ONLY IF: field is guaranteed never used in file system operations.
     */
    boolean noPathTraversal() default true;

    /**
     * Block command injection characters (;, |, &&, `, $, etc.).
     * WHY: Prevent OS command execution via input fields.
     * HOW:
     *   @SafeInput(noCommandInjection = true) // default — blocks "hello; rm -rf /"
     *   private String input;
     * DISABLE ONLY IF: field is a known-safe technical field like a regex pattern.
     */
    boolean noCommandInjection() default true;


    // ══════════════════════════════════════════════════════════════════════
    // WHITESPACE HANDLING
    // Controls how whitespace is treated before and during validation
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Trim leading and trailing whitespace before running all validations.
     * WHY: Prevent accidental failures due to copy-paste spaces around values.
     * HOW:
     *   @SafeInput(trimmed = true)  // default — "  John  " treated as "John"
     *   @SafeInput(trimmed = false) // spaces matter — "  John  " stays as-is
     *   private String firstName;
     */
    boolean trimmed() default true;

    /**
     * Reject any value that contains whitespace characters (spaces, tabs, etc.).
     * WHY: Validate tokens, API keys, passwords, or codes that must have no spaces.
     * HOW:
     *   @SafeInput(noWhitespace = true)
     *   private String apiKey; //  "my key" fails,  "mykey123" passes
     */
    boolean noWhitespace() default false;
}