package com.fund.transfer.bank.service.shared.response.bankaccount;

import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class BankAccountResponseDto {

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
    private String createdByName;

}
