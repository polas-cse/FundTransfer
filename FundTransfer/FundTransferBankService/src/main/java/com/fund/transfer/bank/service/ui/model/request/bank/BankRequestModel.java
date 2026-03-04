package com.fund.transfer.bank.service.ui.model.request.bank;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fund.transfer.bank.service.global.filter.input.SafeInput;
import lombok.*;

import java.time.LocalDateTime;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper = false)
@JsonIgnoreProperties(ignoreUnknown = true)
public class BankRequestModel {

    @SafeInput(
            positiveOrZero = true,
            message = "Bank ID must be a positive number"
    )
    private Long id;

    @SafeInput(
            required = true,
            minLength = 2,
            maxLength = 100,
            noSpecialChars = false,
            noSqlInjection = true,
            noCommandInjection = true,
            message = "Bank name is required (2-100 characters)"
    )
    private String bankName;

    @SafeInput(
            required = true,
            minLength = 2,
            maxLength = 20,
            alphanumeric = true,
            noWhitespace = true,
            noSqlInjection = true,
            message = "Bank code is required and must be alphanumeric (2-20 characters, no spaces)"
    )
    private String bankCode;

    @SafeInput(
            required = true,
            minLength = 8,
            maxLength = 11,
            alphanumeric = true,
            noWhitespace = true,
            pattern = "^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$",
            message = "SWIFT code must be 8 or 11 alphanumeric characters (e.g. DBBKBDDH)"
    )
    private String swiftCode;

    @SafeInput(
            required = true,
            minLength = 2,
            maxLength = 100,
            alphaOnly = false,
            noSpecialChars = true,
            noSqlInjection = true,
            message = "Country is required (2-100 characters)"
    )
    private String country;

    @SafeInput(
            positiveOrZero = true,
            decimalMin = "0.00",
            decimalMax = "999999999999.99",
            integerDigits = 12,
            fractionDigits = 2,
            message = "Capital amount must be 0.00 or greater with max 2 decimal places"
    )
    private float capitalAmount;

    @SafeInput(
            positiveOrZero = true,
            decimalMin = "0.00",
            decimalMax = "999999999999.99",
            integerDigits = 12,
            fractionDigits = 2,
            message = "Total profit must be 0.00 or greater with max 2 decimal places"
    )
    private float totalProfit;

    @SafeInput(
            positiveOrZero = true,
            decimalMin = "0.00",
            decimalMax = "999999999999.99",
            integerDigits = 12,
            fractionDigits = 2,
            message = "Total expense must be 0.00 or greater with max 2 decimal places"
    )
    private float totalExpense;

    private boolean active;

    @JsonProperty("isDeleted")
    private boolean deleted;

    @SafeInput(
            positiveOrZero = true,
            message = "createdBy must be a positive number"
    )
    private Long createdBy;

    @JsonIgnore
    private LocalDateTime createdAt;

    @SafeInput(
            positiveOrZero = true,
            message = "updatedBy must be a positive number"
    )
    private Long updatedBy;

    @JsonIgnore
    private LocalDateTime updatedAt;
}