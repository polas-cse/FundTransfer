package com.fund.transfer.bank.service.service.bank;

import com.fund.transfer.bank.service.shared.request.bank.BankListRequestDto;
import com.fund.transfer.bank.service.shared.request.bank.BankRequestDto;
import com.fund.transfer.bank.service.shared.response.bank.BankListResponseDto;
import com.fund.transfer.bank.service.shared.response.bank.BankResponseDto;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
public class BankServiceImpl implements BankService{


    @Override
    public Mono<BankResponseDto> saveBank(String authHeader, BankRequestDto requestDto) {
        return null;
    }

    @Override
    public Mono<BankResponseDto> updateBank(String authHeader, BankRequestDto requestDto) {
        return null;
    }

    @Override
    public Mono<BankResponseDto> bankDetails(Long userId) {
        return null;
    }

    @Override
    public Flux<BankListResponseDto> bankList(BankListRequestDto requestDto) {
        return null;
    }

    @Override
    public Mono<Long> bankCount(BankListRequestDto requestDto) {
        return null;
    }

    @Override
    public Mono<BankResponseDto> deleteBank(Long userId) {
        return null;
    }
}
