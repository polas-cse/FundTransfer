package com.fund.transfer.bank.service.ui.model.request.bank;

import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class BankListRequestModel {

    private Long createdBy;

}
