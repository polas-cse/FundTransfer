package com.fund.transfer.user.service.ui.model.request.user;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fund.transfer.user.service.global.filter.input.SafeInput;
import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper = false)
@JsonIgnoreProperties(ignoreUnknown = true)
public class BankAccountModel {

    @SafeInput(
            positiveOrZero = true,
            message = "Bank account ID must be a positive number"
    )
    private Long id;

    @SafeInput(
            positive = true,
            message = "Bank ID is required and must be a positive number"
    )
    private Long bankId;

    @SafeInput(
            required = true,
            minLength = 5,
            maxLength = 34,
            numericOnly = false,
            alphanumeric = true,
            noSqlInjection = true,
            noCommandInjection = true,
            message = "Account number is required and must be alphanumeric (5-34 characters)"
    )
    private String accountNumber;

    @SafeInput(
            required = true,
            minLength = 2,
            maxLength = 50,
            noSpecialChars = true,
            noSqlInjection = true,
            message = "Account type is required (2-50 characters)"
    )
    private String accountType;

    @SafeInput(
            positiveOrZero = true,
            decimalMin = "0.00",
            decimalMax = "99999999.99",
            integerDigits = 8,
            fractionDigits = 2,
            message = "Balance must be between 0.00 and 99999999.99"
    )
    private float balance;

    @SafeInput(
            required = true,
            minLength = 3,
            maxLength = 3,
            alphaOnly = true,
            message = "Currency must be a valid 3-letter ISO currency code (e.g. USD, BDT)"
    )
    private String currency;

    @JsonProperty("isPrimary")
    private boolean primary;
}