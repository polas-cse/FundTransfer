package com.fund.transfer.user.service.service.user;

import com.fund.transfer.user.service.data.user.UserRepository;
import com.fund.transfer.user.service.global.security.JwtUtil;
import com.fund.transfer.user.service.shared.request.user.UserListRequestDto;
import com.fund.transfer.user.service.shared.request.user.UserRequestDto;
import com.fund.transfer.user.service.shared.response.user.UserListResponseDto;
import com.fund.transfer.user.service.shared.response.user.UserResponseDto;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);
    private final ReactiveRedisTemplate<String, Object> redisTemplate;
    private final ModelMapper modelMapper;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    @Override
    public Mono<UserResponseDto> saveUser(UserRequestDto requestDto, String authHeader) {
        String cacheKey = "AUTH_CACHE:" + authHeader;

        return redisTemplate.opsForValue()
                .get(cacheKey)
                .map(idStr -> Long.parseLong(idStr.toString()))
                .doOnNext(id -> logger.info("UserId from Redis cache: {}", id))
                .switchIfEmpty(
                        jwtUtil.extractUserIdFromAuthHeader(authHeader)
                                .doOnNext(id -> logger.info("UserId from JWT: {}", id))
                                .flatMap(id ->
                                        redisTemplate.opsForValue()
                                                .set(cacheKey, id.toString(), Duration.ofHours(6))
                                                .thenReturn(id)
                                )
                )
                .flatMap(userId ->
                        userRepository.saveUser(
                                        requestDto.getEmail(),
                                        requestDto.getFirstName(),
                                        requestDto.getLastName(),
                                        requestDto.getPhone(),
                                        requestDto.getGender(),
                                        requestDto.getDateOfBirth(),
                                        requestDto.getImageUrl(),
                                        requestDto.getDownloadUrl(),
                                        userId
                                )
                                .flatMap(entity -> {
                                    logger.info("User entity saved with id: {}", entity.getId());
                                    return userRepository.saveLogins(
                                                    entity.getId(),
                                                    requestDto.getUserName(),
                                                    requestDto.getPassword(),
                                                    userId
                                            )
                                            .thenReturn(entity);
                                })
                )
                .map(entity -> UserResponseDto.builder()
                        .id(entity.getId())
                        .email(entity.getEmail())
                        .firstName(entity.getFirstName())
                        .lastName(entity.getLastName())
                        .phone(entity.getPhone())
                        .gender(entity.getGender())
                        .dateOfBirth(entity.getDateOfBirth())
                        .imageUrl(entity.getImageUrl())
                        .downloadUrl(entity.getDownloadUrl())
                        .userName(requestDto.getUserName())
                        .build()
                )
                .doOnSuccess(u -> {
                    if (u == null) {
                        logger.error("UserResponseDto is null!");
                    } else {
                        logger.info("User saved successfully: {}", u.getEmail());
                    }
                })
                .doOnError(e -> logger.error("Error saving user", e));
    }


    @Override
    public Mono<UserResponseDto> updateUser(UserRequestDto requestDto) {
        return null;
    }

    @Override
    public Mono<UserResponseDto> userDetails(Long userId) {
        return null;
    }

    @Override
    public Mono<UserResponseDto> deleteUser(Long userId) {
        return null;
    }

    @Override
    public Flux<UserListResponseDto> userList(UserListRequestDto requestDto) {
        return null;
    }
}