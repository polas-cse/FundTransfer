package com.fund.transfer.user.service.global.grpc.client;

import com.fund.transfer.user.service.global.messaging.bankaccount.model
        .BankAccountMessage;
import com.fund.transfer.user.service.global.utils.GrpcUtils;
import com.fund.transfer.user.service.grpc.generated.*;
import io.grpc.StatusRuntimeException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class BankAccountGrpcClient {

    private final BankAccountServiceGrpc.BankAccountServiceBlockingStub bankAccountStub;

    public Mono<BankAccountResponse> createBankAccount(BankAccountMessage message) {
        return Mono.fromCallable(() -> attemptToSaveBankAccountGrpcCall(message))
                .retryWhen(
                        Retry.backoff(GrpcUtils.MAX_RETRIES, Duration.ofMillis(GrpcUtils.RETRY_DELAY_MS))
                                .maxBackoff(Duration.ofSeconds(GrpcUtils.MAX_RETRIES_TIME))
                                .filter(ex -> ex instanceof StatusRuntimeException)
                                .doBeforeRetry(retrySignal ->
                                        log.warn("gRPC retry attempt {} time to save bank account for userId: {} due to: {}",
                                                retrySignal.totalRetries() + 1,
                                                message.getUserId(),
                                                retrySignal.failure().getMessage())
                                )
                )
                .subscribeOn(Schedulers.boundedElastic());
    }

    private BankAccountResponse attemptToSaveBankAccountGrpcCall(BankAccountMessage message) {
        BankAccountRequest request = BankAccountRequest.newBuilder()
                .setUserId(message.getUserId())
                .setBankId(message.getBankId())
                .setAccountNumber(message.getAccountNumber())
                .setAccountType(message.getAccountType())
                .setAccountHolderName(message.getAccountHolderName())
                .setBalance(message.getBalance())
                .setCurrency(message.getCurrency())
                .setIsPrimary(message.isPrimary())
                .setCreatedBy(message.getCreatedBy())
                .build();

        log.info("Calling gRPC createBankAccount for userId: {}", message.getUserId());
        return bankAccountStub.createBankAccount(request);
    }

    public Mono<BankAccountBatchResponse> batchUpdateBankAccount(List<BankAccountMessage> messages) {
        return Mono.fromCallable(() -> attemptToBatchUpdateBankAccountGrpcCall(messages))
                .retryWhen(
                        Retry.backoff(GrpcUtils.MAX_RETRIES, Duration.ofMillis(GrpcUtils.RETRY_DELAY_MS))
                                .maxBackoff(Duration.ofSeconds(GrpcUtils.MAX_RETRIES_TIME))
                                .filter(ex -> ex instanceof StatusRuntimeException)
                                .doBeforeRetry(retrySignal ->
                                        log.warn("gRPC retry attempt {} for batch update, count: {} due to: {}",
                                                retrySignal.totalRetries() + 1,
                                                messages.size(),
                                                retrySignal.failure().getMessage())
                                )
                )
                .subscribeOn(Schedulers.boundedElastic());
    }

    private BankAccountBatchResponse attemptToBatchUpdateBankAccountGrpcCall(List<BankAccountMessage> messages) {
        List<BankAccountRequest> requests = messages.stream()
                .map(message -> BankAccountRequest.newBuilder()
                        .setId(message.getId())
                        .setUserId(message.getUserId())
                        .setBankId(message.getBankId())
                        .setAccountNumber(message.getAccountNumber())
                        .setAccountType(message.getAccountType())
                        .setAccountHolderName(message.getAccountHolderName())
                        .setBalance(message.getBalance())
                        .setCurrency(message.getCurrency())
                        .setIsPrimary(message.isPrimary())
                        .setCreatedBy(message.getCreatedBy())
                        .build()
                ).toList();

        BankAccountBatchRequest batchRequest = BankAccountBatchRequest.newBuilder()
                .addAllAccounts(requests)
                .build();

        log.info("Calling gRPC batchUpdateBankAccount, count: {}", messages.size());
        return bankAccountStub.batchUpdateBankAccount(batchRequest);
    }
}