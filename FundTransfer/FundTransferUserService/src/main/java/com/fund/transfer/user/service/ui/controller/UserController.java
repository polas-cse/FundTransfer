package com.fund.transfer.user.service.ui.controller;

import com.fund.transfer.user.service.service.user.UserService;
import com.fund.transfer.user.service.shared.request.user.UserListRequestDto;
import com.fund.transfer.user.service.shared.request.user.UserRequestDto;
import com.fund.transfer.user.service.ui.model.request.user.UserListRequestModel;
import com.fund.transfer.user.service.ui.model.request.user.UserRequestModel;
import com.fund.transfer.user.service.ui.model.response.user.UserListResponseModel;
import com.fund.transfer.user.service.ui.model.response.user.UserResponseModel;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@RestController
@RequiredArgsConstructor
@RequestMapping("user")
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);
    private final ModelMapper modelMapper;
    private final UserService userService;

    @PostMapping
    public Mono<ResponseEntity<UserResponseModel>> saveUser(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody UserRequestModel requestBody){
        UserRequestDto dto = modelMapper.map(requestBody, UserRequestDto.class);
        return userService.saveUser(authHeader, dto)
                .map(responseDto -> modelMapper.map(responseDto, UserResponseModel.class))
                .map(ResponseEntity::ok);
    }

    @PutMapping
    public Mono<ResponseEntity<UserResponseModel>> updateUser(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody UserRequestModel requestBody){
        UserRequestDto dto = modelMapper.map(requestBody, UserRequestDto.class);

        return userService.updateUser(authHeader, dto)
                .map(responseDto-> modelMapper.map(responseDto, UserResponseModel.class))
                .map(ResponseEntity::ok);
    }

    @GetMapping
    public Mono<ResponseEntity<UserResponseModel>> userDetails(@RequestParam Long id){
        return userService.userDetails(id)
                .map(responseDto-> modelMapper.map(responseDto, UserResponseModel.class))
                .map(ResponseEntity::ok);
    }

    @PostMapping("list")
    public Flux<ResponseEntity<UserListResponseModel>> userList(@RequestBody UserListRequestModel requestBody) {

        UserListRequestDto requestDto = modelMapper.map(requestBody, UserListRequestDto.class);

        return userService.userList(requestDto)
                .map(dto -> {
                    UserListResponseModel response = modelMapper.map(dto, UserListResponseModel.class);
                    return ResponseEntity.ok(response);
                });
    }

    @DeleteMapping
    public Mono<ResponseEntity<Boolean>> userDelete(@RequestParam Long id) {
        return userService.deleteUser(id)
                .map(dto -> ResponseEntity.ok(true))
                .defaultIfEmpty(ResponseEntity.ok(false));
    }

}
