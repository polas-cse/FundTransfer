package com.fund.transfer.bank.service.ui.controller;

import com.fund.transfer.bank.service.global.exception.ApiException;
import com.fund.transfer.bank.service.global.filter.output.ResponseSanitizer;
import com.fund.transfer.bank.service.service.bank.BankService;
import com.fund.transfer.bank.service.shared.request.bank.BankListRequestDto;
import com.fund.transfer.bank.service.shared.request.bank.BankRequestDto;
import com.fund.transfer.bank.service.ui.model.request.bank.BankListRequestModel;
import com.fund.transfer.bank.service.ui.model.request.bank.BankRequestModel;
import com.fund.transfer.bank.service.ui.model.response.bank.BankListResponseModel;
import com.fund.transfer.bank.service.ui.model.response.bank.BankResponseModel;
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
@RequestMapping("bank")
public class BankController {

    private static final Logger logger = LoggerFactory.getLogger(BankController.class);
    private final ModelMapper modelMapper;
    private final BankService bankService;
    private final ResponseSanitizer responseSanitizer;

    @PostMapping
    public Mono<ResponseEntity<BankResponseModel>> saveBank(
            @RequestHeader(value = "Authorization", required = true)
            @NotBlank(message = "Authorization header is required") String authHeader,
            @RequestBody @Valid BankRequestModel requestBody) {

        logger.info("Save bank request received");

        BankRequestDto dto = modelMapper.map(requestBody, BankRequestDto.class);
        return bankService.saveBank(authHeader, dto)
                .map(responseDto -> modelMapper.map(responseDto, BankResponseModel.class))
                .map(responseSanitizer::sanitize)
                .map(ResponseEntity::ok);
    }

    @PutMapping
    public Mono<ResponseEntity<BankResponseModel>> updateBank(
            @RequestHeader(value = "Authorization", required = true)
            @NotBlank(message = "Authorization header is required") String authHeader,
            @RequestBody @Valid BankRequestModel requestBody) {

        if (requestBody.getId() == null) {
            return Mono.error(new ApiException("MISSING_ID", "Bank ID is required for update"));
        }

        logger.info("Update bank request received for id: {}", requestBody.getId());

        BankRequestDto dto = modelMapper.map(requestBody, BankRequestDto.class);
        return bankService.updateBank(authHeader, dto)
                .map(responseDto -> modelMapper.map(responseDto, BankResponseModel.class))
                .map(responseSanitizer::sanitize)
                .map(ResponseEntity::ok);
    }

    @GetMapping
    public Mono<ResponseEntity<BankResponseModel>> bankDetails(
            @RequestParam
            @NotNull(message = "Bank ID is required")
            @Positive(message = "Bank ID must be a positive number") Long id) {

        logger.info("Bank details requested for id: {}", id);

        return bankService.bankDetails(id)
                .map(responseDto -> modelMapper.map(responseDto, BankResponseModel.class))
                .map(responseSanitizer::sanitize)
                .map(ResponseEntity::ok);
    }

    @PostMapping("/list")
    public Mono<ResponseEntity<Map<String, Object>>> bankList(
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

            @RequestBody(required = false) @Valid BankListRequestModel requestBody) {

        logger.info("Bank list requested by: {} (ID: {})", currentUsername, currentUserId);

        BankListRequestDto requestDto = BankListRequestDto.builder()
                .createdBy(requestBody != null ? requestBody.getCreatedBy() : null)
                .limit(limit)
                .offset(offset)
                .search(search)
                .build();

        return bankService.bankList(requestDto)
                .map(dto -> modelMapper.map(dto, BankListResponseModel.class))
                .map(responseSanitizer::sanitize)
                .collectList()
                .zipWith(bankService.bankCount(requestDto))
                .map(tuple -> {
                    List<BankListResponseModel> banks = tuple.getT1();
                    Long totalCount = tuple.getT2();

                    Map<String, Object> response = new HashMap<>();
                    response.put("success", true);
                    response.put("data", banks);
                    response.put("pagination", Map.of(
                            "count", totalCount,
                            "limit", limit,
                            "offset", offset,
                            "hasMore", (offset + limit) < totalCount
                    ));
                    return ResponseEntity.ok(response);
                })
                .doOnError(error ->
                        logger.error("Error in bankList: {}", error.getMessage(), error)
                );
    }

    @DeleteMapping
    public Mono<ResponseEntity<Boolean>> bankDelete(
            @RequestParam
            @NotNull(message = "Bank ID is required")
            @Positive(message = "Bank ID must be a positive number") Long id) {

        logger.info("Delete bank requested for id: {}", id);

        return bankService.deleteBank(id)
                .map(dto -> ResponseEntity.ok(true))
                .defaultIfEmpty(ResponseEntity.ok(false));
    }
}