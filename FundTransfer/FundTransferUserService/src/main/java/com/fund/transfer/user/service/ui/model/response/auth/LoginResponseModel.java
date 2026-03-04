package com.fund.transfer.user.service.ui.model.response.auth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fund.transfer.user.service.global.filter.output.SafeOutput;
import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper = false)
@JsonIgnoreProperties(ignoreUnknown = true)
public class LoginResponseModel {

    private boolean success;

    @SafeOutput(sanitizeHtml = true)
    private String message;

    @SafeOutput(sanitizeHtml = true)
    private String token;

    private Long userId;
}