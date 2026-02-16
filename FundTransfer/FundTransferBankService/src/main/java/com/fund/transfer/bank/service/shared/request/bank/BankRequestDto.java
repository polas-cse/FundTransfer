package com.fund.transfer.bank.service.shared.request.bank;

import lombok.*;

import java.time.LocalDateTime;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class BankRequestDto {

    private Long id;
    private String bankName;
    private String bankCode;
    private String swiftCode;
    private String country;
    private float capitalAmount;
    private float totalProfit;
    private float totalExpense;
    private Boolean status;
    private Boolean isDeleted;
    private Long createdBy;
    private LocalDateTime createdAt;
    private Long updatedBy;
    private LocalDateTime updatedAt;

}
