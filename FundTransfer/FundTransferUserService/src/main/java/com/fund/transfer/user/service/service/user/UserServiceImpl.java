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
    public Mono<UserResponseDto> saveUser(UserRequestDto requestDto, String authHeader) {
        return Mono.fromCallable(() -> {
            try {
                Long userId = jwtUtil.extractUserIdFromAuthHeader(authHeader);
                logger.info("Got user ID from JWT: {}", userId);
                return userId;
            } catch (Exception e) {
                logger.error("Error extracting userId from header: {}", e.getMessage());
                throw new IllegalArgumentException("Invalid or missing authentication token", e);
            }
        })
                .flatMap(userId -> {
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
                .map(model -> modelMapper.map(model, UserResponseDto.class))
                .doOnSuccess(u -> logger.info("User saved successfully: {}", u != null ? u.getEmail() : "null"))
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