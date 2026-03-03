package com.fund.transfer.user.service.global.grpc.client;

import com.fund.transfer.user.service.global.messaging.bankaccount.model
        .BankAccountMessage;
import com.fund.transfer.user.service.global.utils.GrpcUtils;
import com.fund.transfer.user.service.grpc.generated.BankAccountRequest;
import com.fund.transfer.user.service.grpc.generated.BankAccountResponse;
import com.fund.transfer.user.service.grpc.generated.BankAccountServiceGrpc;
import io.grpc.StatusRuntimeException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.util.retry.Retry;

import java.time.Duration;

@Component
@RequiredArgsConstructor
@Slf4j
public class BankAccountGrpcClient {

    private final BankAccountServiceGrpc.BankAccountServiceBlockingStub bankAccountStub;

    public Mono<BankAccountResponse> createBankAccount(BankAccountMessage message) {
        return Mono.fromCallable(() -> attemptGrpcCall(message))
                .retryWhen(
                        Retry.backoff(GrpcUtils.MAX_RETRIES, Duration.ofMillis(GrpcUtils.RETRY_DELAY_MS))
                                .maxBackoff(Duration.ofSeconds(GrpcUtils.MAX_RETRIES_TIME))
                                .filter(ex -> ex instanceof StatusRuntimeException)
                                .doBeforeRetry(retrySignal ->
                                        log.warn("gRPC retry attempt {} for userId: {} due to: {}",
                                                retrySignal.totalRetries() + 1,
                                                message.getUserId(),
                                                retrySignal.failure().getMessage())
                                )
                )
                .subscribeOn(Schedulers.boundedElastic());
    }

    private BankAccountResponse attemptGrpcCall(BankAccountMessage message) {
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
}
