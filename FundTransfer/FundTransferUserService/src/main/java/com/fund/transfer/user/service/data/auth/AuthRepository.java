package com.fund.transfer.user.service.data.auth;

import com.fund.transfer.user.service.data.auth.entity.LoginEntity;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface AuthRepository extends R2dbcRepository<LoginEntity, Long> {

    @Query("SELECT * FROM logins WHERE username = :username AND password = :password")
    Mono<LoginEntity> loginUser(String username, String password);

    @Modifying
    @Query(" INSERT INTO login_logs(user_id, access_token) VALUES (:userId, :accessToken)")
    Mono<Integer> saveLoginLogs(Long userId, String accessToken);



}
