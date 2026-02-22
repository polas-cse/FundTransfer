package com.fund.transfer.bank.service.ui.controller;

import com.fund.transfer.bank.service.service.bank.BankService;
import com.fund.transfer.bank.service.shared.request.bank.BankListRequestDto;
import com.fund.transfer.bank.service.shared.request.bank.BankRequestDto;
import com.fund.transfer.bank.service.ui.model.request.bank.BankListRequestModel;
import com.fund.transfer.bank.service.ui.model.request.bank.BankRequestModel;
import com.fund.transfer.bank.service.ui.model.response.bank.BankListResponseModel;
import com.fund.transfer.bank.service.ui.model.response.bank.BankResponseModel;
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
@RequestMapping("bank")
public class BankController {

    private static final Logger logger = LoggerFactory.getLogger(BankController.class);
    private final ModelMapper modelMapper;
    private final BankService bankService;

    @PostMapping
    public Mono<ResponseEntity<BankResponseModel>> saveBank(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody BankRequestModel requestBody){
        BankRequestDto dto = modelMapper.map(requestBody, BankRequestDto.class);
        return bankService.saveBank(authHeader, dto)
                .map(responseDto -> modelMapper.map(responseDto, BankResponseModel.class))
                .map(ResponseEntity::ok);
    }

    @PutMapping
    public Mono<ResponseEntity<BankResponseModel>> updateBank(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody BankRequestModel requestBody){
        BankRequestDto dto = modelMapper.map(requestBody, BankRequestDto.class);

        return bankService.updateBank(authHeader, dto)
                .map(responseDto-> modelMapper.map(responseDto, BankResponseModel.class))
                .map(ResponseEntity::ok);
    }

    @GetMapping
    public Mono<ResponseEntity<BankResponseModel>> BankDetails(@RequestParam Long id){
        return bankService.bankDetails(id)
                .map(responseDto-> modelMapper.map(responseDto, BankResponseModel.class))
                .map(ResponseEntity::ok);
    }

    @PostMapping("/list")
    public Mono<ResponseEntity<Map<String, Object>>> BankList(
            @RequestHeader("X-User-Id") Long currentUserId,
            @RequestHeader("X-User-Name") String currentUsername,
            @RequestParam(required = false, defaultValue = "10") int limit,
            @RequestParam(required = false, defaultValue = "0") int offset,
            @RequestParam(required = false) String search,
            @RequestBody(required = false) BankListRequestModel requestBody
    ) {
        System.out.println("Requested: " + currentUsername + " (ID: " + currentUserId + ")");

        BankListRequestDto requestDto = BankListRequestDto.builder()
                .createdBy(requestBody != null ? requestBody.getCreatedBy() : null)
                .limit(limit)
                .offset(offset)
                .search(search)
                .build();

        return bankService.bankList(requestDto)
                .map(dto -> modelMapper.map(dto, BankListResponseModel.class))
                .collectList()
                .zipWith(bankService.bankCount(requestDto))
                .map(tuple -> {
                    List<BankListResponseModel> Banks = tuple.getT1();
                    Long totalCount = tuple.getT2();

                    Map<String, Object> response = new HashMap<>();
                    response.put("success", true);
                    response.put("data", Banks);
                    response.put("pagination", Map.of(
                            "count", totalCount,
                            "limit", limit,
                            "offset", offset,
                            "hasMore", (offset + limit) < totalCount
                    ));

                    return ResponseEntity.ok(response);
                })
                .doOnError(error -> {
                    System.err.println("Error in BankList: " + error.getMessage());
                    error.printStackTrace();
                });
    }

    @DeleteMapping
    public Mono<ResponseEntity<Boolean>> BankDelete(@RequestParam Long id) {
        return bankService.deleteBank(id)
                .map(dto -> ResponseEntity.ok(true))
                .defaultIfEmpty(ResponseEntity.ok(false));
    }

}
