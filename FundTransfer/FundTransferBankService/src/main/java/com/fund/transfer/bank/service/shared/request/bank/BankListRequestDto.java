package com.fund.transfer.bank.service.shared.request.bank;

import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class BankListRequestDto {

    private Long createdBy;
    private Integer limit;
    private Integer offset;
    private String search;

}
