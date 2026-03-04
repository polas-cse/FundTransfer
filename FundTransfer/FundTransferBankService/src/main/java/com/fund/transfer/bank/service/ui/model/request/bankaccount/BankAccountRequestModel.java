package com.fund.transfer.bank.service.ui.model.request.bankaccount;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fund.transfer.bank.service.global.filter.input.SafeInput;
import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper = false)
@JsonIgnoreProperties(ignoreUnknown = true)
public class BankAccountRequestModel {

    @SafeInput(
            positiveOrZero = true,
            message = "Bank account ID must be a positive number"
    )
    private Long id;

    @SafeInput(
            positive = true,
            message = "User ID is required and must be a positive number"
    )
    private Long userId;

    @SafeInput(
            positive = true,
            message = "Bank ID is required and must be a positive number"
    )
    private Long bankId;

    @SafeInput(
            required = true,
            minLength = 5,
            maxLength = 34,
            alphanumeric = true,
            noWhitespace = true,
            noSqlInjection = true,
            noCommandInjection = true,
            message = "Account number is required and must be alphanumeric (5-34 characters, no spaces)"
    )
    private String accountNumber;

    @SafeInput(
            required = true,
            minLength = 2,
            maxLength = 50,
            noSpecialChars = true,
            noSqlInjection = true,
            noCommandInjection = true,
            message = "Account type is required (2-50 characters)"
    )
    private String accountType;

    @SafeInput(
            required = true,
            minLength = 2,
            maxLength = 100,
            noSpecialChars = false,
            alphaOnly = false,
            noSqlInjection = true,
            noCommandInjection = true,
            message = "Account holder name is required (2-100 characters)"
    )
    private String accountHolderName;

    @SafeInput(
            positiveOrZero = true,
            decimalMin = "0.00",
            decimalMax = "999999999999.99",
            integerDigits = 12,
            fractionDigits = 2,
            message = "Balance must be 0.00 or greater with max 2 decimal places"
    )
    private float balance;

    @SafeInput(
            required = true,
            minLength = 3,
            maxLength = 3,
            alphaOnly = true,
            noWhitespace = true,
            pattern = "^[A-Z]{3}$",
            message = "Currency must be a valid 3-letter uppercase ISO currency code (e.g. USD, BDT, EUR)"
    )
    private String currency;

    @JsonProperty("isPrimary")
    private boolean primary;

    private boolean active;
}