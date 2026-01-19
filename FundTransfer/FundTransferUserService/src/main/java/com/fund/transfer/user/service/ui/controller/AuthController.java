package com.fund.transfer.user.service.ui.controller;

import com.fund.transfer.user.service.service.auth.LoginService;
import com.fund.transfer.user.service.shared.request.auth.LoginDto;
import com.fund.transfer.user.service.ui.model.request.auth.LoginRequestModel;
import com.fund.transfer.user.service.ui.model.response.auth.LoginResponseModel;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequiredArgsConstructor
@RequestMapping("auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private final ModelMapper modelMapper;
    private final LoginService loginService;

    @PostMapping("/login")
    public Mono<ResponseEntity<LoginResponseModel>> userLogin(@RequestBody LoginRequestModel request) {
        logger.info("user login method called from auth controller");

        LoginDto dto = modelMapper.map(request, LoginDto.class);

        return loginService.userLogin(dto)
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.badRequest().build());
    }

    @PostMapping("/logout")
    public Mono<Boolean> userlogout(@RequestParam String userName) {
        logger.info("user logout method called from auth controller");
        return loginService.logout(userName);
    }


}
