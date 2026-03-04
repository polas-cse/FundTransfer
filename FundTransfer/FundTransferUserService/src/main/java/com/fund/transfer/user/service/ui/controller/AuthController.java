package com.fund.transfer.user.service.ui.controller;

import com.fund.transfer.user.service.global.filter.output.ResponseSanitizer;
import com.fund.transfer.user.service.service.auth.LoginService;
import com.fund.transfer.user.service.shared.request.auth.LoginDto;
import com.fund.transfer.user.service.ui.model.request.auth.LoginRequestModel;
import com.fund.transfer.user.service.ui.model.response.auth.LoginResponseModel;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@Validated
@RestController
@RequiredArgsConstructor
@RequestMapping("auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private final ModelMapper modelMapper;
    private final LoginService loginService;
    private final ResponseSanitizer responseSanitizer;

    @PostMapping("/login")
    public Mono<ResponseEntity<LoginResponseModel>> userLogin(
            @RequestBody @Valid LoginRequestModel request) {

        logger.info("Login attempt for userName: {}", request.getUserName());

        LoginDto dto = modelMapper.map(request, LoginDto.class);

        return loginService.userLogin(dto)
                .map(responseSanitizer::sanitize)
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }

    @PostMapping("/logout")
    public Mono<ResponseEntity<Boolean>> userLogout(
            @RequestParam
            @NotBlank(message = "Username is required")
            @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters") String userName) {

        logger.info("Logout requested for userName: {}", userName);

        return loginService.logout(userName)
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }
}