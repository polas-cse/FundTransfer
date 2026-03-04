package com.fund.transfer.user.service.ui.model.request.user;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
@JsonIgnoreProperties(ignoreUnknown = true)
public class BankAccountModel {

    private Long id;
    private Long bankId;
    private String accountNumber;
    private String accountType;
    private float balance;
    private String currency;
    @JsonProperty("isPrimary")
    private boolean isPrimary;

}
