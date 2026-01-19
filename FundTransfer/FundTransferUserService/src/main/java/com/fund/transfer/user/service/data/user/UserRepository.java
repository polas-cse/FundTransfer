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
        INSERT INTO users(email, first_name, last_name, phone, gender, date_of_birth, image_url, download_url, created_by)
        VALUES (:email, :firstName, :lastName, :phone, :gender, :dateOfBirth, :imageUrl, :downloadUrl, :createdBy) 
        RETURNING *
        """)
    Mono<UserEntity> saveUser(String email, String firstName, String lastName, String phone, String gender,
                              LocalDate dateOfBirth, String imageUrl, String downloadUrl, Long createdBy);

    @Query("""
        UPDATE users
        SET email = :email, first_name = :firstName, last_name = :lastName, phone = :phone,
            gender = :gender, date_of_birth = :dateOfBirth, image_url = :imageUrl, download_url = :downloadUrl, 
            updated_by = :updatedBy, updated_at = NOW() 
        WHERE id = :userId 
        RETURNING *
        """)
    Mono<UserEntity> updateUser(Long userId, String email, String firstName, String lastName, String phone,
                                String gender, LocalDate dateOfBirth, String imageUrl, String downloadUrl, Long updatedBy);

    @Query("""
        SELECT id, email, first_name, last_name, phone, gender, date_of_birth, image_url, download_url, created_by, updated_by
        FROM users 
        WHERE id = :userId AND active = true
        """)
    Mono<UserEntity> userDetails(Long userId);

    @Query("""
        UPDATE users
        SET active = false 
        WHERE id = :userId 
        RETURNING *
        """)
    Mono<UserEntity> userDelete(Long userId);

    @Query("""
        SELECT id, email, first_name, last_name, phone, gender, date_of_birth, image_url, download_url, created_by, updated_by
        FROM users
        WHERE (:userId IS NULL OR id = :userId) 
        AND active = true 
        ORDER BY created_at DESC
        """)
    Flux<UserEntity> userList(@Nullable Long userId);
}