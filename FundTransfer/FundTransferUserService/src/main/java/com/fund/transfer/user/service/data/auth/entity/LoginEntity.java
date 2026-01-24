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
    private String userName;
    private String password;
    private String salt;
    private boolean isPwdReset;
    private boolean twoFactorEnabled;
    private Timestamp lockedUntil;
    private int loginAttempts;
    private Timestamp lastLoginAt;
    private Timestamp loginTime;
    private Timestamp expireAt;
    private String accessToken;
    private String refreshToken;
    private String device;
    private String ipAddress;
    private String location;
    private String createdBy;
    private Timestamp createdAt;
    private String updatedBy;
    private Timestamp updatedAt;


}
