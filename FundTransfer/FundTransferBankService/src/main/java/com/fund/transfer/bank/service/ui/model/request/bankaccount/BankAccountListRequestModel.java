package com.fund.transfer.bank.service.ui.model.request.bankaccount;

import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class BankAccountListRequestModel {

    private Long createdBy;
    private Integer limit;
    private Integer offset;
    private String search;

}
