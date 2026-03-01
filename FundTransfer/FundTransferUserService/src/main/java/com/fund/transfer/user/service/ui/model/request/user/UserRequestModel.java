package com.fund.transfer.user.service.ui.model.request.user;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import java.time.LocalDate;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserRequestModel {

    private Long id;
    private String userName;
    private String password;
    private String email;
    private String firstName;
    private String lastName;
    private String phone;
    private String gender;
    private LocalDate dateOfBirth;
    private String imageUrl;
    private String downloadUrl;
    private boolean active;

    private Long bankId;
    private String accountNumber;
    private String accountType;
    private float balance;
    private String currency;
    @JsonProperty("isPrimary")
    private boolean isPrimary;

    private Long createdBy;
    private Long updatedBy;

}
