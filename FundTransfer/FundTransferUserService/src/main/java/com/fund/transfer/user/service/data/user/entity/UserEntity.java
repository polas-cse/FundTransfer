package com.fund.transfer.user.service.data.user.entity;

import lombok.*;

import java.sql.Timestamp;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class UserEntity {

    private long id;
    private String email;
    private String first_name;
    private String last_name;
    private String phone;
    private String gender;
    private Timestamp date_of_birth;
    private String image_url;
    private String download_url;
    private boolean active;
    private String created_by;
    private Timestamp created_at;
    private String updated_by;
    private Timestamp updated_at;


}
