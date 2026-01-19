package com.fund.transfer.user.service.service.user;

import com.fund.transfer.user.service.shared.request.user.UserListRequestDto;
import com.fund.transfer.user.service.shared.request.user.UserRequestDto;
import com.fund.transfer.user.service.shared.response.user.UserListResponseDto;
import com.fund.transfer.user.service.shared.response.user.UserResponseDto;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface UserService {

    Mono<UserResponseDto> saveUser(UserRequestDto requestDto, String authHeader);
    Mono<UserResponseDto> updateUser(UserRequestDto requestDto);
    Mono<UserResponseDto> userDetails(Long userId);
    Mono<UserResponseDto> deleteUser(Long userId);
    Flux<UserListResponseDto> userList(UserListRequestDto requestDto);

}
