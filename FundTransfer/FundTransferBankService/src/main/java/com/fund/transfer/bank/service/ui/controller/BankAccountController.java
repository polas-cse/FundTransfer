package com.fund.transfer.bank.service.ui.controller;

import com.fund.transfer.bank.service.service.bankaccount.BankAccountService;
import com.fund.transfer.bank.service.shared.request.bankaccount.BankAccountListRequestDto;
import com.fund.transfer.bank.service.shared.request.bankaccount.BankAccountRequestDto;
import com.fund.transfer.bank.service.ui.model.request.bankaccount.BankAccountListRequestModel;
import com.fund.transfer.bank.service.ui.model.request.bankaccount.BankAccountRequestModel;
import com.fund.transfer.bank.service.ui.model.response.bankaccount.BankAccountListResponseModel;
import com.fund.transfer.bank.service.ui.model.response.bankaccount.BankAccountResponseModel;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("bank-account")
public class BankAccountController {

    private static final Logger logger = LoggerFactory.getLogger(BankAccountController.class);
    private final ModelMapper modelMapper;
    private final BankAccountService bankAccountService;

    @PostMapping
    public Mono<ResponseEntity<BankAccountResponseModel>> saveBankAccount(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody BankAccountRequestModel requestBody) {
        BankAccountRequestDto dto = modelMapper.map(requestBody, BankAccountRequestDto.class);
        return bankAccountService.saveBankAccount(authHeader, dto)
                .map(responseDto -> modelMapper.map(responseDto, BankAccountResponseModel.class))
                .map(ResponseEntity::ok);
    }

    @PutMapping
    public Mono<ResponseEntity<BankAccountResponseModel>> updateBankAccount(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody BankAccountRequestModel requestBody) {
        BankAccountRequestDto dto = modelMapper.map(requestBody, BankAccountRequestDto.class);
        return bankAccountService.updateBankAccount(authHeader, dto)
                .map(responseDto -> modelMapper.map(responseDto, BankAccountResponseModel.class))
                .map(ResponseEntity::ok);
    }

    @GetMapping
    public Mono<ResponseEntity<BankAccountResponseModel>> bankAccountDetails(@RequestParam Long id) {
        return bankAccountService.bankAccountDetails(id)
                .map(responseDto -> modelMapper.map(responseDto, BankAccountResponseModel.class))
                .map(ResponseEntity::ok);
    }

    @PostMapping("/list")
    public Mono<ResponseEntity<Map<String, Object>>> bankAccountList(
            @RequestHeader("X-User-Id") Long currentUserId,
            @RequestHeader("X-User-Name") String currentUsername,
            @RequestParam(required = false, defaultValue = "10") int limit,
            @RequestParam(required = false, defaultValue = "0") int offset,
            @RequestParam(required = false) String search,
            @RequestBody(required = false) BankAccountListRequestModel requestBody) {

        System.out.println("Requested: " + currentUsername + " (ID: " + currentUserId + ")");

        BankAccountListRequestDto requestDto = BankAccountListRequestDto.builder()
                .createdBy(requestBody != null ? requestBody.getCreatedBy() : null)
                .limit(limit)
                .offset(offset)
                .search(search)
                .build();

        return bankAccountService.bankAccountList(requestDto)
                .map(dto -> modelMapper.map(dto, BankAccountListResponseModel.class))
                .collectList()
                .zipWith(bankAccountService.bankAccountCount(requestDto))
                .map(tuple -> {
                    List<BankAccountListResponseModel> bankAccounts = tuple.getT1();
                    Long totalCount = tuple.getT2();

                    Map<String, Object> response = new HashMap<>();
                    response.put("success", true);
                    response.put("data", bankAccounts);
                    response.put("pagination", Map.of(
                            "count", totalCount,
                            "limit", limit,
                            "offset", offset,
                            "hasMore", (offset + limit) < totalCount
                    ));

                    return ResponseEntity.ok(response);
                })
                .doOnError(error -> {
                    System.err.println("Error in bankAccountList: " + error.getMessage());
                    error.printStackTrace();
                });
    }

    @DeleteMapping
    public Mono<ResponseEntity<Boolean>> bankAccountDelete(@RequestParam Long id) {
        return bankAccountService.deleteBankAccount(id)
                .map(dto -> ResponseEntity.ok(true))
                .defaultIfEmpty(ResponseEntity.ok(false));
    }
}