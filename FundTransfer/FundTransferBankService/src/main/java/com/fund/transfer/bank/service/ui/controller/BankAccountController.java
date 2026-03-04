package com.fund.transfer.bank.service.ui.controller;

import com.fund.transfer.bank.service.global.exception.ApiException;
import com.fund.transfer.bank.service.global.filter.output.ResponseSanitizer;
import com.fund.transfer.bank.service.service.bankaccount.BankAccountService;
import com.fund.transfer.bank.service.shared.request.bankaccount.BankAccountListRequestDto;
import com.fund.transfer.bank.service.shared.request.bankaccount.BankAccountRequestDto;
import com.fund.transfer.bank.service.ui.model.request.bankaccount.BankAccountListRequestModel;
import com.fund.transfer.bank.service.ui.model.request.bankaccount.BankAccountRequestModel;
import com.fund.transfer.bank.service.ui.model.response.bankaccount.BankAccountListResponseModel;
import com.fund.transfer.bank.service.ui.model.response.bankaccount.BankAccountResponseModel;
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
@RequestMapping("bank-account")
public class BankAccountController {

    private static final Logger logger = LoggerFactory.getLogger(BankAccountController.class);
    private final ModelMapper modelMapper;
    private final BankAccountService bankAccountService;
    private final ResponseSanitizer responseSanitizer;

    @PostMapping
    public Mono<ResponseEntity<BankAccountResponseModel>> saveBankAccount(
            @RequestHeader(value = "Authorization", required = true)
            @NotBlank(message = "Authorization header is required") String authHeader,
            @RequestBody @Valid BankAccountRequestModel requestBody) {

        logger.info("Save bank account request received");

        BankAccountRequestDto dto = modelMapper.map(requestBody, BankAccountRequestDto.class);
        return bankAccountService.saveBankAccount(authHeader, dto)
                .map(responseDto -> modelMapper.map(responseDto, BankAccountResponseModel.class))
                .map(responseSanitizer::sanitize)
                .map(ResponseEntity::ok);
    }

    @PutMapping
    public Mono<ResponseEntity<BankAccountResponseModel>> updateBankAccount(
            @RequestHeader(value = "Authorization", required = true)
            @NotBlank(message = "Authorization header is required") String authHeader,
            @RequestBody @Valid BankAccountRequestModel requestBody) {

        if (requestBody.getId() == null) {
            return Mono.error(new ApiException("MISSING_ID", "Bank account ID is required for update"));
        }

        logger.info("Update bank account request received for id: {}", requestBody.getId());

        BankAccountRequestDto dto = modelMapper.map(requestBody, BankAccountRequestDto.class);
        return bankAccountService.updateBankAccount(authHeader, dto)
                .map(responseDto -> modelMapper.map(responseDto, BankAccountResponseModel.class))
                .map(responseSanitizer::sanitize)
                .map(ResponseEntity::ok);
    }

    @GetMapping
    public Mono<ResponseEntity<BankAccountResponseModel>> bankAccountDetails(
            @RequestParam
            @NotNull(message = "Bank account ID is required")
            @Positive(message = "Bank account ID must be a positive number") Long id) {

        logger.info("Bank account details requested for id: {}", id);

        return bankAccountService.bankAccountDetails(id)
                .map(responseDto -> modelMapper.map(responseDto, BankAccountResponseModel.class))
                .map(responseSanitizer::sanitize)
                .map(ResponseEntity::ok);
    }

    @PostMapping("/list")
    public Mono<ResponseEntity<Map<String, Object>>> bankAccountList(
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

            @RequestBody(required = false) @Valid BankAccountListRequestModel requestBody) {

        logger.info("Bank account list requested by: {} (ID: {})", currentUsername, currentUserId);

        BankAccountListRequestDto requestDto = BankAccountListRequestDto.builder()
                .createdBy(requestBody != null ? requestBody.getCreatedBy() : null)
                .limit(limit)
                .offset(offset)
                .search(search)
                .build();

        return bankAccountService.bankAccountList(requestDto)
                .map(dto -> modelMapper.map(dto, BankAccountListResponseModel.class))
                .map(responseSanitizer::sanitize)
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
                .doOnError(error ->
                        logger.error("Error in bankAccountList: {}", error.getMessage(), error)
                );
    }

    @DeleteMapping
    public Mono<ResponseEntity<Boolean>> bankAccountDelete(
            @RequestParam
            @NotNull(message = "Bank account ID is required")
            @Positive(message = "Bank account ID must be a positive number") Long id) {

        logger.info("Delete bank account requested for id: {}", id);

        return bankAccountService.deleteBankAccount(id)
                .map(dto -> ResponseEntity.ok(true))
                .defaultIfEmpty(ResponseEntity.ok(false));
    }
}