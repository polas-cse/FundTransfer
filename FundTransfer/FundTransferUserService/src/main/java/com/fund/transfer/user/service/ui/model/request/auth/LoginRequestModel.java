package com.fund.transfer.user.service.ui.model.request.auth;

import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class LoginRequestModel {

    private String userName;
    private String password;

}
