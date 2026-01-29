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

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

    @PostMapping("/list")
    public Mono<ResponseEntity<Map<String, Object>>> userList(
            @RequestHeader("X-User-Id") Long currentUserId,
            @RequestHeader("X-User-Name") String currentUsername,
            @RequestParam(required = false, defaultValue = "10") int limit,
            @RequestParam(required = false, defaultValue = "0") int offset,
            @RequestParam(required = false) String search,
            @RequestBody(required = false) UserListRequestModel requestBody
    ) {
        System.out.println("Requested: " + currentUsername + " (ID: " + currentUserId + ")");

        UserListRequestDto requestDto = UserListRequestDto.builder()
                .createdBy(requestBody != null ? requestBody.getCreatedBy() : null)
                .limit(limit)
                .offset(offset)
                .search(search)
                .build();

        return userService.userList(requestDto)
                .map(dto -> modelMapper.map(dto, UserListResponseModel.class))
                .collectList()
                .zipWith(userService.userCount(requestDto))
                .map(tuple -> {
                    List<UserListResponseModel> users = tuple.getT1();
                    Long totalCount = tuple.getT2();

                    Map<String, Object> response = new HashMap<>();
                    response.put("success", true);
                    response.put("data", users);
                    response.put("pagination", Map.of(
                            "count", totalCount,
                            "limit", limit,
                            "offset", offset,
                            "hasMore", (offset + limit) < totalCount
                    ));

                    return ResponseEntity.ok(response);
                })
                .doOnError(error -> {
                    System.err.println("Error in userList: " + error.getMessage());
                    error.printStackTrace();
                });
    }

    @DeleteMapping
    public Mono<ResponseEntity<Boolean>> userDelete(@RequestParam Long id) {
        return userService.deleteUser(id)
                .map(dto -> ResponseEntity.ok(true))
                .defaultIfEmpty(ResponseEntity.ok(false));
    }

}
