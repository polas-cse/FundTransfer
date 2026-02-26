package com.fund.transfer.bank.service.service.bankaccount;

import com.fund.transfer.bank.service.shared.request.bankaccount.BankAccountListRequestDto;
import com.fund.transfer.bank.service.shared.request.bankaccount.BankAccountRequestDto;
import com.fund.transfer.bank.service.shared.response.bankaccount.BankAccountListResponseDto;
import com.fund.transfer.bank.service.shared.response.bankaccount.BankAccountResponseDto;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface BankAccountService {

    Mono<BankAccountResponseDto> saveBankAccount(String authHeader, BankAccountRequestDto requestDto);
    Mono<BankAccountResponseDto> updateBankAccount(String authHeader, BankAccountRequestDto requestDto);
    Mono<BankAccountResponseDto> bankAccountDetails(Long userId);
    Flux<BankAccountListResponseDto> bankAccountList(BankAccountListRequestDto requestDto);
    Mono<Long> bankAccountCount(BankAccountListRequestDto requestDto);
    Mono<BankAccountResponseDto> deleteBankAccount(Long userId);

}
