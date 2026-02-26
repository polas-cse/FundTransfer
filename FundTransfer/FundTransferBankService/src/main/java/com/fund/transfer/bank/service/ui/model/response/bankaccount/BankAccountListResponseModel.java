package com.fund.transfer.bank.service.ui.model.response.bankaccount;

import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class BankAccountListResponseModel {

    private Long id;
    private Long userId;
    private String userName;
    private Long bankId;
    private String bankName;
    private String accountNumber;
    private String accountType;
    private String accountHolderName;
    private float balance;
    private String currency;
    private boolean isPrimary;
    private boolean active;

}
