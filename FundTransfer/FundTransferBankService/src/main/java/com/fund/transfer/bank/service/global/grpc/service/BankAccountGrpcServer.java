package com.fund.transfer.bank.service.global.grpc.service;

import com.fund.transfer.bank.service.data.bankaccount.BankAccountRepository;
import com.fund.transfer.bank.service.global.messaging.bankaccount.model.BankAccountMessage;
import com.fund.transfer.bank.service.grpc.generated.*;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.devh.boot.grpc.server.service.GrpcService;
import reactor.core.publisher.Flux;

import java.util.List;

@GrpcService
@RequiredArgsConstructor
@Slf4j
public class BankAccountGrpcServer extends BankAccountServiceGrpc.BankAccountServiceImplBase {

    private final BankAccountRepository bankAccountRepository;

    @Override
    public void createBankAccount(BankAccountRequest request,
                                  StreamObserver<BankAccountResponse> responseObserver) {
        log.info("gRPC createBankAccount received for userId: {}", request.getUserId());

        bankAccountRepository.saveBankAccount(
                        request.getUserId(),
                        request.getBankId(),
                        request.getAccountNumber(),
                        request.getAccountType(),
                        request.getAccountHolderName(),
                        request.getBalance(),
                        request.getCurrency(),
                        request.getIsPrimary(),
                        request.getCreatedBy())
                .subscribe(
                        account -> {
                            log.info("Bank account created via gRPC id: {}", account.getId());
                            responseObserver.onNext(BankAccountResponse.newBuilder()
                                    .setId(account.getId())
                                    .setAccountNumber(account.getAccountNumber())
                                    .setAccountHolderName(account.getAccountHolderName())
                                    .setSuccess(true)
                                    .setMessage("Bank account created successfully")
                                    .build());
                            responseObserver.onCompleted();
                        },
                        error -> {
                            log.error("gRPC bank account creation failed for userId: {}", request.getUserId(), error);
                            responseObserver.onError(Status.INTERNAL
                                    .withDescription("Failed to create bank account: " + error.getMessage())
                                    .asRuntimeException());
                        }
                );
    }

    @Override
    public void batchUpdateBankAccount(BankAccountBatchRequest request,
                                       StreamObserver<BankAccountBatchResponse> responseObserver) {
        log.info("gRPC batchUpdateBankAccount received, count: {}", request.getAccountsCount());

        Flux.fromIterable(request.getAccountsList())
                .flatMap(r -> bankAccountRepository.updateBankAccount(
                        r.getId(),
                        r.getAccountNumber(),
                        r.getAccountType(),
                        r.getAccountHolderName(),
                        r.getBalance(),
                        r.getCurrency(),
                        r.getIsPrimary(),
                        r.getCreatedBy()
                ), 10)
                .collectList()
                .subscribe(
                        accounts -> {
                            log.info("Batch updated {} bank accounts via gRPC", accounts.size());

                            List<BankAccountResponse> responses = accounts.stream()
                                    .map(account -> BankAccountResponse.newBuilder()
                                            .setId(account.getId())
                                            .setAccountNumber(account.getAccountNumber())
                                            .setAccountHolderName(account.getAccountHolderName())
                                            .setSuccess(true)
                                            .setMessage("Updated successfully")
                                            .build()
                                    ).toList();

                            responseObserver.onNext(BankAccountBatchResponse.newBuilder()
                                    .addAllAccounts(responses)
                                    .setSuccess(true)
                                    .setMessage("Batch updated " + accounts.size() + " bank accounts")
                                    .build());
                            responseObserver.onCompleted();
                        },
                        error -> {
                            log.error("gRPC batch update failed: {}", error.getMessage());
                            responseObserver.onError(Status.INTERNAL
                                    .withDescription("Batch update failed: " + error.getMessage())
                                    .asRuntimeException());
                        }
                );
    }

}
