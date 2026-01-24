package com.fund.transfer.user.service.data.user;

import com.fund.transfer.user.service.data.user.entity.UserEntity;
import jakarta.annotation.Nullable;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDate;

@Repository
public interface UserRepository extends R2dbcRepository<UserEntity, Long> {

    @Query("""
        WITH inserted_user AS (
            INSERT INTO users(email, first_name, last_name, phone, gender, date_of_birth, image_url, download_url, created_by)
            VALUES (:email, :firstName, :lastName, :phone, :gender, :dateOfBirth, :imageUrl, :downloadUrl, :createdBy) 
            RETURNING *
        )
        SELECT u.id, u.email, u.first_name, u.last_name, u.phone, u.gender, 
               u.date_of_birth, u.image_url, u.download_url, u.active, u.created_by, u.updated_by,
               l.user_name
        FROM inserted_user u
        LEFT JOIN logins l ON u.id = l.user_id
        """)
    Mono<UserEntity> saveUser(String email, String firstName, String lastName, String phone, String gender,
                              LocalDate dateOfBirth, String imageUrl, String downloadUrl, Long createdBy);

    @Query("""
        INSERT INTO logins(user_id, user_name, password, created_by)
        VALUES (:userId, :user_name, :password, :createdBy)
        """)
    Mono<Integer> saveLogins(Long userId, String user_name, String password, Long createdBy);

    @Query("""
        WITH updated_user AS (
            UPDATE users SET email = :email, first_name = :firstName, last_name = :lastName, phone = :phone,
                gender = :gender, date_of_birth = :dateOfBirth, image_url = :imageUrl, download_url = :downloadUrl, 
                active = :active, updated_by = :updatedBy, updated_at = NOW()  
            WHERE id = :userId 
            RETURNING *
        )
        SELECT u.id, u.email, u.first_name, u.last_name, u.phone, u.gender, 
               u.date_of_birth, u.image_url, u.download_url, u.active, u.created_by, u.updated_by,
               l.user_name
        FROM updated_user u
        LEFT JOIN logins l ON u.id = l.user_id
        """)
    Mono<UserEntity> updateUser(Long userId, String email, String firstName, String lastName, String phone,
                                String gender, LocalDate dateOfBirth, String imageUrl, String downloadUrl,
                                boolean active, Long updatedBy);

    @Query("""
        SELECT u.id, u.email, u.first_name, u.last_name, u.phone, u.gender, u.date_of_birth, u.image_url,
        u.download_url, u.active, u.created_by, u.updated_by, l.user_name
        FROM users u
        LEFT JOIN logins l ON u.id = l.user_id
        WHERE u.id = :userId AND u.active = true
        """)
    Mono<UserEntity> userDetails(Long userId);

    @Query("""
        WITH deleted_user AS (
            UPDATE users SET active = false WHERE id = :userId RETURNING *
        )
        SELECT u.id, u.email, u.first_name, u.last_name, u.phone, u.gender, u.date_of_birth, u.image_url, 
        u.download_url, u.active, u.created_by, u.updated_by, l.user_name
        FROM deleted_user u
        LEFT JOIN logins l ON u.id = l.user_id
        """)
    Mono<UserEntity> userDelete(Long userId);

    @Query("""
        SELECT u.id, u.email, u.first_name, u.last_name, u.phone, u.gender, 
               u.date_of_birth, u.image_url, u.download_url, u.active, u.created_by, u.updated_by, 
               l.user_name
        FROM users u 
        LEFT JOIN logins l ON u.id = l.user_id 
        WHERE (:userId IS NULL OR u.id = :userId) AND u.active = true
        ORDER BY u.created_at DESC
        """)
    Flux<UserEntity> userList(@Nullable Long userId);
}