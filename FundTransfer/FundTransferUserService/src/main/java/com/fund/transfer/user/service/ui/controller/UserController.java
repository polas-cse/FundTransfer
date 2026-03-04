package com.fund.transfer.user.service.ui.controller;

import com.fund.transfer.user.service.global.exception.ApiException;
import com.fund.transfer.user.service.global.filter.output.ResponseSanitizer;
import com.fund.transfer.user.service.service.user.UserService;
import com.fund.transfer.user.service.shared.request.user.UserListRequestDto;
import com.fund.transfer.user.service.shared.request.user.UserRequestDto;
import com.fund.transfer.user.service.ui.model.request.user.UserListRequestModel;
import com.fund.transfer.user.service.ui.model.request.user.UserRequestModel;
import com.fund.transfer.user.service.ui.model.response.user.UserListResponseModel;
import com.fund.transfer.user.service.ui.model.response.user.UserResponseModel;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Validated
@RestController
@RequiredArgsConstructor
@RequestMapping("user")
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);
    private final ModelMapper modelMapper;
    private final UserService userService;
    private final ResponseSanitizer responseSanitizer;

    @PostMapping
    public Mono<ResponseEntity<UserResponseModel>> saveUser(
            @RequestHeader(value = "X-User-Role", required = false) String role,
            @RequestHeader(value = "Authorization", required = true)
            @NotBlank(message = "Authorization header is required") String authHeader,
            @RequestBody @Valid UserRequestModel requestBody) {

        logger.info("Save user request received");

        UserRequestDto dto = modelMapper.map(requestBody, UserRequestDto.class);
        return userService.saveUser(authHeader, dto)
                .map(responseDto -> modelMapper.map(responseDto, UserResponseModel.class))
                .map(model -> responseSanitizer.sanitize(model, role))
                .map(ResponseEntity::ok);
    }

    @PutMapping
    public Mono<ResponseEntity<UserResponseModel>> updateUser(
            @RequestHeader(value = "X-User-Role", required = false) String role,
            @RequestHeader(value = "Authorization", required = true)
            @NotBlank(message = "Authorization header is required") String authHeader,
            @RequestBody @Valid UserRequestModel requestBody) {

        if (requestBody.getId() == null) {
            return Mono.error(new ApiException("MISSING_ID", "User ID is required for update"));
        }

        logger.info("Update user request received for id: {}", requestBody.getId());

        UserRequestDto dto = modelMapper.map(requestBody, UserRequestDto.class);
        return userService.updateUser(authHeader, dto)
                .map(responseDto -> modelMapper.map(responseDto, UserResponseModel.class))
                .map(model -> responseSanitizer.sanitize(model, role))
                .map(ResponseEntity::ok);
    }

    @GetMapping
    public Mono<ResponseEntity<UserResponseModel>> userDetails(
            @RequestHeader(value = "X-User-Role", required = false) String role,
            @RequestParam
            @NotNull(message = "User ID is required")
            @Positive(message = "User ID must be a positive number") Long id) {

        logger.info("User details requested for id: {}", id);

        return userService.userDetails(id)
                .map(responseDto -> modelMapper.map(responseDto, UserResponseModel.class))
                .map(model -> responseSanitizer.sanitize(model, role))
                .map(ResponseEntity::ok);
    }

    @PostMapping("/list")
    public Mono<ResponseEntity<Map<String, Object>>> userList(
            @RequestHeader(value = "X-User-Role", required = false) String role,

            @RequestHeader("X-User-Id")
            @NotNull(message = "X-User-Id header is required")
            @Positive(message = "X-User-Id must be a positive number") Long currentUserId,

            @RequestHeader("X-User-Name")
            @NotBlank(message = "X-User-Name header is required")
            @Size(max = 100, message = "X-User-Name too long") String currentUsername,

            @RequestParam(required = false, defaultValue = "10")
            @Min(value = 1, message = "Limit must be at least 1")
            @Max(value = 100, message = "Limit must not exceed 100") int limit,

            @RequestParam(required = false, defaultValue = "0")
            @Min(value = 0, message = "Offset must be 0 or greater") int offset,

            @RequestParam(required = false)
            @Size(max = 100, message = "Search term too long") String search,

            @RequestBody(required = false) @Valid UserListRequestModel requestBody) {

        logger.info("User list requested by: {} (ID: {})", currentUsername, currentUserId);

        UserListRequestDto requestDto = UserListRequestDto.builder()
                .createdBy(requestBody != null ? requestBody.getCreatedBy() : null)
                .limit(limit)
                .offset(offset)
                .search(search)
                .build();

        return userService.userList(requestDto)
                .map(dto -> modelMapper.map(dto, UserListResponseModel.class))
                .map(model -> responseSanitizer.sanitize(model, role))
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
                .doOnError(error ->
                        logger.error("Error in userList: {}", error.getMessage(), error)
                );
    }

    @DeleteMapping
    public Mono<ResponseEntity<Boolean>> userDelete(
            @RequestHeader(value = "X-User-Role", required = false) String role,
            @RequestParam
            @NotNull(message = "User ID is required")
            @Positive(message = "User ID must be a positive number") Long id) {

        logger.info("Delete user requested for id: {}", id);

        return userService.deleteUser(id)
                .map(dto -> ResponseEntity.ok(true))
                .map(model -> responseSanitizer.sanitize(model, role))
                .defaultIfEmpty(ResponseEntity.ok(false));
    }
}