package com.fund.transfer.user.service.service.auth;

import com.fund.transfer.user.service.data.auth.AuthRepository;
import com.fund.transfer.user.service.shared.auth.LoginDto;
import com.fund.transfer.user.service.ui.model.response.auth.LoginResponseModel;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class LoginServiceImpl implements LoginService {

    private final AuthRepository authRepository;

    @Override
    @Cacheable(value = "userLogin", key = "#loginDto.userName")
    public Mono<LoginResponseModel> userLogin(LoginDto loginDto) {

        return authRepository
                .loginUser(loginDto.getUserName(), loginDto.getPassword())
                .map(user -> new LoginResponseModel("Login Successful"))
                .switchIfEmpty(Mono.just(new LoginResponseModel("Invalid username or password")))
                .onErrorResume(error -> {
                    return Mono.just(new LoginResponseModel("Internal server error!"));
                });
    }
}

