package com.fund.transfer.user.service.data.user.entity;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class UserEntity {

    private Long id;
    private String email;
    private String first_name;
    private String last_name;
    private String phone;
    private String gender;
    private LocalDate date_of_birth;
    private String image_url;
    private String download_url;
    private Boolean active;
    private Long created_by;
    private LocalDateTime created_at;
    private Long updated_by;
    private LocalDateTime updated_at;
}