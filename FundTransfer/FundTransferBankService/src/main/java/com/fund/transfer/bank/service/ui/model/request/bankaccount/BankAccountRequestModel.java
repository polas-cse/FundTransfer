package com.fund.transfer.bank.service.ui.model.request.bankaccount;

import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class BankAccountRequestModel {

    private Long id;
    private Long userId;
    private Long bankId;
    private String accountNumber;
    private String accountType;
    private String accountHolderName;
    private float balance;
    private String currency;
    private boolean isPrimary;
    private boolean active;

}
