package com.fund.transfer.user.service.shared.request.user;

import lombok.*;

import java.time.LocalDate;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class UserRequestDto {

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
    private Long createdBy;
    private Long updatedBy;

}
