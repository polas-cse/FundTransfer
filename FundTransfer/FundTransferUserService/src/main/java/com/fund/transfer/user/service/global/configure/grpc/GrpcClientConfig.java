package com.fund.transfer.user.service.global.configure.grpc;

import com.fund.transfer.user.service.grpc.generated.BankAccountServiceGrpc;
import io.grpc.Channel;
import io.grpc.ManagedChannelBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GrpcClientConfig {

    @Value("${grpc.client.bank-service.address:localhost:9191}")
    private String bankServiceAddress;

    @Bean
    public Channel bankAccountServiceChannel() {
        // Parse address like "localhost:9191" or with scheme like "static://localhost:9191"
        String address = bankServiceAddress;
        if (address.contains("://")) {
            address = address.split("://")[1];
        }
        String[] parts = address.split(":");
        String host = parts[0];
        int port = parts.length > 1 ? Integer.parseInt(parts[1]) : 9191;
        
        return ManagedChannelBuilder
                .forAddress(host, port)
                .usePlaintext()
                .build();
    }

    @Bean
    public BankAccountServiceGrpc.BankAccountServiceBlockingStub bankAccountServiceBlockingStub(Channel bankAccountServiceChannel) {
        return BankAccountServiceGrpc.newBlockingStub(bankAccountServiceChannel);
    }

}
