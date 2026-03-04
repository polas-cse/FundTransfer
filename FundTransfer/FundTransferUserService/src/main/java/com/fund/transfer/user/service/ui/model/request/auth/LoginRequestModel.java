package com.fund.transfer.user.service.ui.model.request.auth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fund.transfer.user.service.global.filter.input.SafeInput;
import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper = false)
@JsonIgnoreProperties(ignoreUnknown = true)
public class LoginRequestModel {

    @SafeInput(
            required = true,
            minLength = 3,
            maxLength = 50,
            noWhitespace = true,
            noSpecialChars = false,
            noSqlInjection = true,
            noCommandInjection = true,
            message = "Username is required (3-50 characters, no spaces)"
    )
    private String userName;

    @SafeInput(
            required = true,
            minLength = 6,
            maxLength = 100,
            noWhitespace = true,
            allowHtml = false,
            noSqlInjection = true,
            noPathTraversal = true,
            noCommandInjection = true,
            message = "Password is required (6-100 characters)"
    )

    @ToString.Exclude
    private String password;

}