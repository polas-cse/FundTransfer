package com.fund.transfer.bank.service.ui.model.request.bankaccount;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
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
public class BankAccountListRequestModel {

    @SafeInput(
            positiveOrZero = true,
            message = "createdBy must be a positive number"
    )
    private Long createdBy;

    @SafeInput(
            minValue = 1,
            maxValue = 100,
            message = "limit must be between 1 and 100"
    )
    private Integer limit;

    @SafeInput(
            positiveOrZero = true,
            message = "offset must be 0 or greater"
    )
    private Integer offset;

    @SafeInput(
            maxLength = 100,
            noSpecialChars = false,
            noSqlInjection = true,
            noCommandInjection = true,
            message = "Invalid search input"
    )
    private String search;

}
