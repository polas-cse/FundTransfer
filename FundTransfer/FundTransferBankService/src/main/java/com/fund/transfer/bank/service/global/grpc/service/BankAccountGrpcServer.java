package com.fund.transfer.bank.service.global.grpc.service;

import com.fund.transfer.bank.service.data.bankaccount.BankAccountRepository;
import com.fund.transfer.bank.service.grpc.generated.BankAccountServiceGrpc;
import com.fund.transfer.bank.service.grpc.generated.BankAccountRequest;
import com.fund.transfer.bank.service.grpc.generated.BankAccountResponse;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.devh.boot.grpc.server.service.GrpcService;

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
    public void updateBankAccount(BankAccountRequest request,
                                  StreamObserver<BankAccountResponse> responseObserver) {
        log.info("gRPC updateBankAccount received for userId: {}", request.getUserId());

        bankAccountRepository.updateBankAccount(
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
                            log.info("Bank account updated via gRPC id: {}", account.getId());
                            responseObserver.onNext(BankAccountResponse.newBuilder()
                                    .setId(account.getId())
                                    .setAccountNumber(account.getAccountNumber())
                                    .setAccountHolderName(account.getAccountHolderName())
                                    .setSuccess(true)
                                    .setMessage("Bank account updated successfully")
                                    .build());
                            responseObserver.onCompleted();
                        },
                        error -> {
                            log.error("gRPC bank account update failed for userId: {}", request.getUserId(), error);
                            responseObserver.onError(Status.INTERNAL
                                    .withDescription("Failed to update bank account: " + error.getMessage())
                                    .asRuntimeException());
                        }
                );
    }

}
