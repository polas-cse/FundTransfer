package com.fund.transfer.user.service.ui.controller;

import com.fund.transfer.user.service.service.user.UserService;
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
            @RequestBody UserRequestModel requestBody,
            @RequestHeader(value = "Authorization", required = false) String authHeader){
        UserRequestDto dto = modelMapper.map(requestBody, UserRequestDto.class);
        return userService.saveUser(dto, authHeader)
                .map(responseDto -> modelMapper.map(responseDto, UserResponseModel.class))
                .map(ResponseEntity::ok);
    }

    @PutMapping
    public Mono<ResponseEntity<UserResponseModel>> updateUser(@RequestBody UserRequestModel requestBody){
        return null;
    }

    @GetMapping
    public Mono<ResponseEntity<UserResponseModel>> userDetails(@RequestParam Long id){
        return null;
    }

    @GetMapping("list")
    public Flux<ResponseEntity<UserListResponseModel>> userList(@RequestBody UserListRequestModel requestBody){
        return null;
    }

    @DeleteMapping
    public ResponseEntity<Boolean> userDelete(@RequestParam Long id){
        return null;
    }

}
