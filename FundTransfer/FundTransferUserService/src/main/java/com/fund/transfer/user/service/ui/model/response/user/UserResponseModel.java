package com.fund.transfer.user.service.ui.model.response.user;

import lombok.*;

import java.time.LocalDate;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class UserResponseModel {

    private Long id;
    private String email;
    private String firstName;
    private String lastName;
    private String phone;
    private String gender;
    private LocalDate dateOfBirth;
    private String imageUrl;
    private String downloadUrl;
    private Long createdBy;
    private Long updatedBy;

}
