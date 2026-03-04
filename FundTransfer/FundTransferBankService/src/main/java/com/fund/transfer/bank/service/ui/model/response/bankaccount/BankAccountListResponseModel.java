package com.fund.transfer.bank.service.ui.model.response.bankaccount;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fund.transfer.bank.service.global.filter.output.SafeOutput;
import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper = false)
@JsonIgnoreProperties(ignoreUnknown = true)
public class BankAccountListResponseModel {

    private Long id;

    @SafeOutput(hidden = true)
    private Long userId;

    @SafeOutput(sanitizeHtml = true)
    private String userName;

    @SafeOutput(hidden = true)
    private Long bankId;

    @SafeOutput(sanitizeHtml = true)
    private String bankName;

    @SafeOutput(masked = true, visibleChars = 4)
    private String accountNumber;

    @SafeOutput(sanitizeHtml = true)
    private String accountType;

    @SafeOutput(sanitizeHtml = true)
    private String accountHolderName;

    private float balance;

    @SafeOutput(sanitizeHtml = true)
    private String currency;

    @JsonProperty("isPrimary")
    private boolean primary;

    private boolean active;
}