package com.fund.transfer.user.service.shared.response.auth;

import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class LoginDto {

    private String userName;
    private String password;

}
