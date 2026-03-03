package com.fund.transfer.user.service.global.messaging.user.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BankAccountMessage implements Serializable {
    private Long userId;
    private Long bankId;
    private String accountNumber;
    private String accountType;
    private String accountHolderName;
    private float balance;
    private String currency;
    private boolean isPrimary;
    private Long createdBy;
    private int retryCount;
}