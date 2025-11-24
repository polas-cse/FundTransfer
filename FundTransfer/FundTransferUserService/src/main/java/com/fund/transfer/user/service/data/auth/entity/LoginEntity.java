package com.fund.transfer.user.service.data.auth.entity;

import lombok.*;
import org.springframework.data.annotation.Id;

import java.sql.Timestamp;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class LoginEntity {

    private long id;
    private long user_id;
    private String username;
    private String password;
    private String salt;
    private boolean is_pwd_reset;
    private boolean two_factor_enabled;
    private Timestamp locked_until;
    private int login_attempts;
    private Timestamp last_login_at;
    private Timestamp login_time;
    private Timestamp expire_at;
    private String access_token;
    private String refresh_token;
    private String device;
    private String ip_address;
    private String location;
    private String created_by;
    private Timestamp created_at;
    private String updated_by;
    private Timestamp updated_at;


}
