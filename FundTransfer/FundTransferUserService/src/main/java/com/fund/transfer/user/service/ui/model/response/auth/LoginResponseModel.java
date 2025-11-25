package com.fund.transfer.user.service.ui.model.response.auth;

import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class LoginResponseModel {

    private boolean success;
    private String message;
    private String token;
    private Long userId;

}
