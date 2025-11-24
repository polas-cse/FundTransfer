package com.fund.transfer.user.service.service.auth;

import com.fund.transfer.user.service.shared.auth.LoginDto;
import com.fund.transfer.user.service.ui.model.response.auth.LoginResponseModel;
import reactor.core.publisher.Mono;

public interface LoginService {


    Mono<LoginResponseModel> userLogin(LoginDto loginDto);


}
