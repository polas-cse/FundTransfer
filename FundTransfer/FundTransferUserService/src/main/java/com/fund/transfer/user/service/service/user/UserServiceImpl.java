package com.fund.transfer.user.service.service.user;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fund.transfer.user.service.data.user.UserRepository;
import com.fund.transfer.user.service.global.exception.ApiException;
import com.fund.transfer.user.service.global.security.JwtUtil;
import com.fund.transfer.user.service.shared.request.user.UserListRequestDto;
import com.fund.transfer.user.service.shared.request.user.UserRequestDto;
import com.fund.transfer.user.service.shared.response.user.UserListResponseDto;
import com.fund.transfer.user.service.shared.response.user.UserResponseDto;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
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
                        userRepository.saveUser(requestDto.getEmail(), requestDto.getFirstName(), requestDto.getLastName(), requestDto.getPhone(),
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
                .onErrorMap(ex -> {
                    if (ex instanceof DuplicateKeyException) {
                        if (ex.getMessage().contains("uk_users_username")) {
                            return new ApiException("USER_NAME_EXISTS", "Username already exists");
                        }
                        if (ex.getMessage().contains("uk_users_email")) {
                            return new ApiException("USER_EMAIL_EXISTS", "This email is already registered");
                        }
                        return new ApiException("DUPLICATE_KEY", "Duplicate value found");
                    }
                    return ex;
                });
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
                .flatMap(userId -> {
                    String userDetailsCacheKey = "USER_DETAILS_CACHE:" + userId;
                    logger.info("Deleting cache for key: {}", userDetailsCacheKey);

                    return userRepository.updateUser(requestDto.getId(),requestDto.getEmail(),requestDto.getFirstName(),requestDto.getLastName(),
                                    requestDto.getPhone(), requestDto.getGender(), requestDto.getDateOfBirth(),requestDto.getImageUrl(),
                                    requestDto.getDownloadUrl(),userId)
                            .flatMap(entity ->
                                    redisTemplate.delete(userDetailsCacheKey)
                                            .doOnNext(deleted ->
                                                    logger.info("User details cache deleted successfully: {}", deleted)
                                            )
                                            .thenReturn(entity)
                            );
                })
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
                .onErrorMap(ex -> {
                    if (ex instanceof DuplicateKeyException) {
                        if (ex.getMessage().contains("uk_users_email")) {
                            return new ApiException("USER_EMAIL_EXISTS", "This email is already registered");
                        }
                        return new ApiException("DUPLICATE_KEY", "Duplicate value found");
                    }
                    return ex;
                });
    }

    @Override
    public Mono<UserResponseDto> userDetails(Long userId) {
        String cacheKey = "USER_DETAILS_CACHE:" + userId;
        logger.info("Checking cache for key: {}", cacheKey);

        return redisTemplate.opsForValue()
                .get(cacheKey)
                .doOnNext(data -> logger.info("Cache HIT for userId: {}", userId))
                .flatMap(cachedData -> {
                    try {
                        String jsonString = cachedData.toString();
                        logger.debug("Cached JSON data: {}", jsonString);

                        UserResponseDto dto = objectMapper.readValue(jsonString, UserResponseDto.class);
                        logger.info("Successfully deserialized user from cache: {}", dto.getEmail());
                        return Mono.just(dto);
                    } catch (Exception e) {
                        logger.error("Error deserializing cached user details for userId: {}", userId, e);
                        return redisTemplate.delete(cacheKey).then(Mono.empty());
                    }
                })
                .switchIfEmpty(
                        Mono.defer(() -> {
                            logger.info("Cache MISS for userId: {}, fetching from database", userId);
                            return userRepository.userDetails(userId)
                                    .flatMap(userDetails -> {
                                        logger.info("User Details fetched from Database for userId: {}", userId);

                                        UserResponseDto responseDto = UserResponseDto.builder().id(userDetails.getId()).userName(userDetails.getUsername())
                                                .email(userDetails.getEmail()).firstName(userDetails.getFirstName()).lastName(userDetails.getLastName())
                                                .phone(userDetails.getPhone()).gender(userDetails.getGender()).dateOfBirth(userDetails.getDateOfBirth())
                                                .imageUrl(userDetails.getImageUrl()).downloadUrl(userDetails.getDownloadUrl()).build();

                                        try {
                                            String jsonData = objectMapper.writeValueAsString(responseDto);
                                            logger.debug("Serialized JSON for caching: {}", jsonData);

                                            return redisTemplate.opsForValue()
                                                    .set(cacheKey, jsonData, Duration.ofHours(6))
                                                    .doOnSuccess(result ->
                                                            logger.info("User details cached successfully for userId: {} with TTL 6 hours", userId)
                                                    )
                                                    .doOnError(error ->
                                                            logger.error("Failed to cache user details for userId: {}", userId, error)
                                                    )
                                                    .thenReturn(responseDto);
                                        } catch (Exception e) {
                                            logger.error("Error serializing user details for caching, userId: {}", userId, e);
                                            return Mono.just(responseDto);
                                        }
                                    });
                        })
                )
                .doOnSuccess(dto -> {
                    if (dto != null) {
                        logger.info("User details retrieved successfully: {}", dto.getEmail());
                    } else {
                        logger.warn("User details not found for userId: {}", userId);
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