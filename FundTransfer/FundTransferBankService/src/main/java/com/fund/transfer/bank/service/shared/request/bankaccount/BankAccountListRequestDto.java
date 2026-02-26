package com.fund.transfer.bank.service.shared.request.bankaccount;

import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class BankAccountListRequestDto {

    private Long createdBy;
    private Integer limit;
    private Integer offset;
    private String search;

}
