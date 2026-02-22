package com.fund.transfer.bank.service.data.bank.entity;

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
public class Bank {

    private Long id;
    private String bankName;
    private String bankCode;
    private String swiftCode;
    private String country;
    private float capitalAmount;
    private float totalProfit;
    private float totalExpense;
    private boolean active;
    private boolean isDeleted;
    private Long createdBy;
    @Transient
    private String createdByName;
    private LocalDateTime createdAt;
    private Long updatedBy;
    private LocalDateTime updatedAt;

}
