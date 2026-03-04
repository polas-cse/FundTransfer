package com.fund.transfer.user.service.ui.model.request.user;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fund.transfer.user.service.global.configure.jackson.FlexibleListDeserializer;
import com.fund.transfer.user.service.global.filter.input.SafeInput;
import jakarta.validation.constraints.Past;
import lombok.*;

import java.time.LocalDate;
import java.util.List;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserRequestModel {

    private Long id;

    @SafeInput(required = true, minLength = 3, maxLength = 50)
    private String userName;

    @SafeInput(required = true, minLength = 6, maxLength = 100)
    private String password;

    @SafeInput(required = true, emailFormat = true, maxLength = 100)
    private String email;

    @SafeInput(required = true, minLength = 2, maxLength = 50)
    private String firstName;

    @SafeInput(required = true, minLength = 2, maxLength = 50)
    private String lastName;

    @SafeInput(maxLength = 20)
    private String phone;

    @SafeInput(maxLength = 10)
    private String gender;

    @Past(message = "Date of birth must be in the past")
    private LocalDate dateOfBirth;

    @SafeInput(maxLength = 500)
    private String imageUrl;

    @SafeInput(maxLength = 500)
    private String downloadUrl;

    private boolean active;

    @JsonDeserialize(using = FlexibleListDeserializer.class)
    private List<BankAccountModel> bankAccounts;

    private Long createdBy;
    private Long updatedBy;
}