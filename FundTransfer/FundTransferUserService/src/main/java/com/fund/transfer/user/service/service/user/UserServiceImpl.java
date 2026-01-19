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

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);
    private final ReactiveRedisTemplate<String, Object> redisTemplate;
    private final ModelMapper modelMapper;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    @Override
    public Mono<UserResponseDto> saveUser(UserRequestDto requestDto) {
        logger.info("=== Starting saveUser ===");
        logger.info("Request: {}", requestDto);

        return jwtUtil.getUserId()
                .doOnNext(userId -> logger.info("✅ Got user ID from JWT: {}", userId))
                .doOnError(e -> logger.error("❌ Error getting user ID from JWT", e))
                .flatMap(userId -> {
                    logger.info("🔄 Calling repository.saveUser with params:");
                    logger.info("  email: {}", requestDto.getEmail());
                    logger.info("  firstName: {}", requestDto.getFirstName());
                    logger.info("  lastName: {}", requestDto.getLastName());
                    logger.info("  phone: {}", requestDto.getPhone());
                    logger.info("  gender: {}", requestDto.getGender());
                    logger.info("  dateOfBirth: {}", requestDto.getDateOfBirth());
                    logger.info("  createdBy: {}", userId);

                    return userRepository.saveUser(
                            requestDto.getEmail(),
                            requestDto.getFirstName(),
                            requestDto.getLastName(),
                            requestDto.getPhone(),
                            requestDto.getGender(),
                            requestDto.getDateOfBirth(),
                            requestDto.getImageUrl(),
                            requestDto.getDownloadUrl(),
                            userId
                    );
                })
                .doOnNext(entity -> {
                    logger.info("✅ Entity returned from DB: {}", entity);
                    logger.info("  ID: {}", entity.getId());
                    logger.info("  Email: {}", entity.getEmail());
                })
                .doOnError(e -> logger.error("❌ Error from repository", e))
                .map(model -> {
                    UserResponseDto dto = modelMapper.map(model, UserResponseDto.class);
                    logger.info("✅ Mapped to DTO: {}", dto);
                    return dto;
                })
                .doOnSuccess(u -> logger.info("✅ Final success: {}", u))
                .doOnError(e -> logger.error("❌ Final error", e));
    }

//    @Override
//    public Mono<UserResponseDto> saveUser(UserRequestDto requestDto) {
//        return jwtUtil.getUserId()
//                .doOnNext(userId -> logger.info("Current user ID: {}", userId))
//                .flatMap(userId ->
//                        userRepository.saveUser(
//                                requestDto.getEmail(),
//                                requestDto.getFirstName(),
//                                requestDto.getLastName(),
//                                requestDto.getPhone(),
//                                requestDto.getGender(),
//                                requestDto.getDateOfBirth(),
//                                requestDto.getImageUrl(),
//                                requestDto.getDownloadUrl(),
//                                userId
//                        )
//                )
//                .doOnNext(entity -> logger.info("Entity from DB: {}", entity))
//                .map(model -> modelMapper.map(model, UserResponseDto.class))
//                .doOnSuccess(u -> logger.info("User saved successfully: {}", u != null ? u.getEmail() : "null"))
//                .doOnError(e -> logger.error("Error saving user", e));
//    }

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