package com.fund.transfer.bank.service.ui.model.response.bank;

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
public class BankListResponseModel {

    private Long id;

    @SafeOutput(sanitizeHtml = true)
    private String bankName;

    @SafeOutput(sanitizeHtml = true)
    private String bankCode;

    @SafeOutput(masked = true, visibleChars = 4)
    private String swiftCode;

    @SafeOutput(sanitizeHtml = true)
    private String country;

    private float capitalAmount;
    private float totalProfit;
    private float totalExpense;
    private boolean active;

    @JsonProperty("isDeleted")
    private boolean deleted;
}