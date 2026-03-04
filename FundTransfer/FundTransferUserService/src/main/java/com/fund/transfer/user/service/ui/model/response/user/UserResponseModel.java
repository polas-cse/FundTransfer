package com.fund.transfer.user.service.ui.model.response.user;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fund.transfer.user.service.global.filter.output.SafeOutput;
import lombok.*;

import java.time.LocalDate;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper = false)
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserResponseModel {

    private Long id;

    @SafeOutput(sanitizeHtml = true)
    private String userName;

    @SafeOutput(sanitizeHtml = true)
    private String email;

    @SafeOutput(sanitizeHtml = true)
    private String firstName;

    @SafeOutput(sanitizeHtml = true)
    private String lastName;

    @SafeOutput(masked = true, visibleChars = 4, visibleToRoles = {"ADMIN"})
    private String phone;

    @SafeOutput(sanitizeHtml = true)
    private String gender;

    private LocalDate dateOfBirth;
    private boolean active;

    @SafeOutput(sanitizeHtml = true, truncate = true, maxLength = 500)
    private String imageUrl;

    @SafeOutput(sanitizeHtml = true, truncate = true, maxLength = 500)
    private String downloadUrl;
}
