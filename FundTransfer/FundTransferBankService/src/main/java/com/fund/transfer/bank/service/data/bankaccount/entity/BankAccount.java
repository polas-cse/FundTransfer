package com.fund.transfer.bank.service.data.bankaccount.entity;

import lombok.*;
import org.springframework.data.annotation.Transient;

import java.time.LocalDateTime;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class BankAccount {

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
    private Long createdBy;
    @Transient
    private String createdByName;
    private LocalDateTime createdAt;
    private Long updatedBy;
    private LocalDateTime updatedAt;

}
