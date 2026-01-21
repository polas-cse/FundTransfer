package com.fund.transfer.user.service.service.user;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.transaction.annotation.Transactional;
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
    private final ObjectMapper objectMapper;
    private final JwtUtil jwtUtil;

    @Override
    @Transactional
    public Mono<UserResponseDto> saveUser(String authHeader, UserRequestDto requestDto) {
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
                        userRepository.saveUser( requestDto.getEmail(), requestDto.getFirstName(), requestDto.getLastName(), requestDto.getPhone(),
                                        requestDto.getGender(), requestDto.getDateOfBirth(), requestDto.getImageUrl(), requestDto.getDownloadUrl(), userId)
                                .flatMap(entity -> {
                                    logger.info("User entity saved with id: {}", entity.getId());
                                    return userRepository.saveLogins(entity.getId(), requestDto.getUserName(), requestDto.getPassword(), userId)
                                            .thenReturn(entity);
                                })
                )
                .map(entity -> UserResponseDto.builder().id(entity.getId()).email(entity.getEmail()).firstName(entity.getFirstName())
                        .lastName(entity.getLastName()).phone(entity.getPhone()).gender(entity.getGender()).dateOfBirth(entity.getDateOfBirth())
                        .imageUrl(entity.getImageUrl()).downloadUrl(entity.getDownloadUrl()).userName(requestDto.getUserName()).build()
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
    @Transactional
    public Mono<UserResponseDto> updateUser(String authHeader, UserRequestDto requestDto) {
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
                        userRepository.updateUser(requestDto.getId(), requestDto.getEmail(), requestDto.getFirstName(), requestDto.getLastName(), requestDto.getPhone(),
                                        requestDto.getGender(), requestDto.getDateOfBirth(), requestDto.getImageUrl(), requestDto.getDownloadUrl(), userId)

                )
                .map(entity -> UserResponseDto.builder().id(entity.getId()).email(entity.getEmail()).firstName(entity.getFirstName())
                        .lastName(entity.getLastName()).phone(entity.getPhone()).gender(entity.getGender()).dateOfBirth(entity.getDateOfBirth())
                        .imageUrl(entity.getImageUrl()).downloadUrl(entity.getDownloadUrl()).userName(requestDto.getUserName()).build()
                )
                .doOnSuccess(u -> {
                    if (u == null) {
                        logger.error("UserResponseDto is null!");
                    } else {
                        logger.info("User updated successfully: {}", u.getEmail());
                    }
                })
                .doOnError(e -> logger.error("Error saving user", e));
    }

    @Override
    public Mono<UserResponseDto> userDetails(Long userId) {
        String cacheKey = "USER_DETAILS_CACHE:" + userId;

        return redisTemplate.opsForValue()
                .get(cacheKey)
                .flatMap(cachedData -> {
                    logger.info("User Details from Redis cache for userId: {}", userId);
                    try {
                        UserResponseDto dto = objectMapper.readValue(cachedData.toString(), UserResponseDto.class);
                        return Mono.just(dto);
                    } catch (Exception e) {
                        logger.error("Error deserializing cached user details", e);
                        return Mono.empty();
                    }
                })
                .switchIfEmpty(
                        userRepository.userDetails(userId)
                                .flatMap(userDetails -> {
                                    logger.info("User Details from Database for userId: {}", userId);
                                    UserResponseDto responseDto = UserResponseDto.builder()
                                            .id(userDetails.getId())
                                            .userName(userDetails.getUsername())
                                            .email(userDetails.getEmail())
                                            .firstName(userDetails.getFirstName())
                                            .lastName(userDetails.getLastName())
                                            .phone(userDetails.getPhone())
                                            .gender(userDetails.getGender())
                                            .dateOfBirth(userDetails.getDateOfBirth())
                                            .imageUrl(userDetails.getImageUrl())
                                            .downloadUrl(userDetails.getDownloadUrl())
                                            .build();
                                    try {
                                        String jsonData = objectMapper.writeValueAsString(responseDto);
                                        return redisTemplate.opsForValue()
                                                .set(cacheKey, jsonData, Duration.ofHours(6))
                                                .doOnSuccess(result -> logger.info("User details cached successfully"))
                                                .thenReturn(responseDto);
                                    } catch (Exception e) {
                                        logger.error("Error caching user details", e);
                                        return Mono.just(responseDto);
                                    }
                                })
                )
                .doOnSuccess(dto -> {
                    if (dto != null) {
                        logger.info("User details retrieved successfully: {}", dto.getEmail());
                    }else{
                        logger.info("User details not retrieved successfully");
                    }
                })
                .doOnError(e -> logger.error("Error retrieving user details for userId: {}", userId, e));
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