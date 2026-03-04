package com.fund.transfer.user.service.global.messaging.bankaccount.publisher;

import com.fund.transfer.user.service.global.messaging.bankaccount.model.BankAccountMessage;
import com.fund.transfer.user.service.global.utils.RabbitMQUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.connection.CorrelationData;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class BankAccountEventPublisher {

    private final RabbitTemplate rabbitTemplate;

    public Mono<Void> publishSaveBankAccount(BankAccountMessage message) {
        return Mono.fromRunnable(() -> {
            try {
                String correlationId = UUID.randomUUID().toString();
                CorrelationData correlationData = new CorrelationData(correlationId);

                rabbitTemplate.convertAndSend(
                        RabbitMQUtils.BANK_ACCOUNT_EXCHANGE,
                        RabbitMQUtils.BANK_ACCOUNT_ROUTING_CREATE_KEY,
                        message,
                        msg -> {
                            msg.getMessageProperties().setHeader("correlation_id", correlationId);
                            return msg;
                        },
                        correlationData
                );
                log.info("Published event to save bank account for userId: {}, correlationId: {}", message.getUserId(), correlationId);
            } catch (Exception e) {
                log.error("Failed to publish event to save bank account for userId: {}", message.getUserId(), e);
                throw new RuntimeException("RabbitMQ publish failed to save bank account", e);
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    public Mono<Void> publishUpdateBankAccount(BankAccountMessage message) {
        return Mono.fromRunnable(() -> {
            try {
                String correlationId = UUID.randomUUID().toString();
                CorrelationData correlationData = new CorrelationData(correlationId);

                rabbitTemplate.convertAndSend(
                        RabbitMQUtils.BANK_ACCOUNT_EXCHANGE,
                        RabbitMQUtils.BANK_ACCOUNT_ROUTING_UPDATE_KEY,
                        message,
                        msg -> {
                            msg.getMessageProperties().setHeader("correlation_id", correlationId);
                            return msg;
                        },
                        correlationData
                );
                log.info("Published event to update bank account for userId: {}, correlationId: {}", message.getUserId(), correlationId);
            } catch (Exception e) {
                log.error("Failed to publish event to update bank account for userId: {}", message.getUserId(), e);
                throw new RuntimeException("RabbitMQ publish failed to update bank account", e);
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

}