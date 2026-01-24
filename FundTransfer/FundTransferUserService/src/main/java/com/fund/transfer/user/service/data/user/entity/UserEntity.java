package com.fund.transfer.user.service.data.user.entity;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
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
    private String userName;
    private String email;
    private String firstName;
    private String lastName;
    private String phone;
    private String gender;
    private LocalDate dateOfBirth;
    private String imageUrl;
    private String downloadUrl;
    private Boolean active;
    private Long createdBy;
    private LocalDateTime createdAt;
    private Long updatedBy;
    private LocalDateTime updatedAt;
}