package com.fund.transfer.user.service.service.auth;

import com.fund.transfer.user.service.data.auth.AuthRepository;
import com.fund.transfer.user.service.global.security.JwtUtil;
import com.fund.transfer.user.service.shared.auth.LoginDto;
import com.fund.transfer.user.service.ui.model.response.auth.LoginResponseModel;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class LoginServiceImpl implements LoginService {

    private static final Logger logger = LoggerFactory.getLogger(LoginServiceImpl.class);
    private final AuthRepository authRepository;
    private final ReactiveRedisTemplate<String, Object> redisTemplate;
    private final JwtUtil jwtUtil;

    @Override
    public Mono<LoginResponseModel> userLogin(LoginDto loginDto) {
        String cacheKey = "LOGIN_CACHE:" + loginDto.getUserName();

        return redisTemplate.opsForValue()
                .get(cacheKey)
                .cast(LoginResponseModel.class)
                .doOnNext(cache -> logger.info("Cache hit for user: {}", loginDto.getUserName()))
                .switchIfEmpty(
                        authRepository.loginUser(loginDto.getUserName(), loginDto.getPassword())
                                .flatMap(user -> {
                                    String token = jwtUtil.generateToken(
                                            user.getUsername(),
                                            user.getId()
                                    );

                                    LoginResponseModel response = new LoginResponseModel(
                                            true,
                                            "Login Successful",
                                            token,
                                            user.getId()
                                    );

                                    return redisTemplate.opsForValue()
                                            .set(cacheKey, response, Duration.ofHours(6))
                                            .thenReturn(response);
                                })
                                .switchIfEmpty(
                                        Mono.just(new LoginResponseModel(false, "Invalid credentials", null, null))
                                )
                )
                .onErrorResume(error -> {
                    logger.error("Login error: {}", error.getMessage());
                    return Mono.just(new LoginResponseModel(false, "Internal server error", null, null));
                });
    }

    @Override
    public Mono<Boolean> logout(String userName) {
        return redisTemplate.delete("LOGIN_CACHE:" + userName).map(count -> count > 0);
    }
}