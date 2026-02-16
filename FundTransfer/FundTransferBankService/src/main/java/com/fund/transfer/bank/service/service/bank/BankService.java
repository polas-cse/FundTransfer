package com.fund.transfer.bank.service.service.bank;

import com.fund.transfer.bank.service.shared.request.bank.BankListRequestDto;
import com.fund.transfer.bank.service.shared.request.bank.BankRequestDto;
import com.fund.transfer.bank.service.shared.response.bank.BankListResponseDto;
import com.fund.transfer.bank.service.shared.response.bank.BankResponseDto;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface BankService {

    Mono<BankResponseDto> saveBank(String authHeader, BankRequestDto requestDto);
    Mono<BankResponseDto> updateBank(String authHeader, BankRequestDto requestDto);
    Mono<BankResponseDto> bankDetails(Long userId);
    Flux<BankListResponseDto> bankList(BankListRequestDto requestDto);
    Mono<Long> bankCount(BankListRequestDto requestDto);
    Mono<BankResponseDto> deleteBank(Long userId);

}
