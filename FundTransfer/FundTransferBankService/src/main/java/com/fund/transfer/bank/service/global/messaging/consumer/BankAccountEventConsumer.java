package com.fund.transfer.bank.service.global.messaging.consumer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fund.transfer.bank.service.data.bankaccount.BankAccountRepository;
import com.fund.transfer.bank.service.global.config.RabbitMQConfig;
import com.fund.transfer.bank.service.global.messaging.model.BankAccountMessage;
import com.rabbitmq.client.Channel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.AmqpHeaders;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class BankAccountEventConsumer {

    private final BankAccountRepository bankAccountRepository;
    private final RabbitTemplate rabbitTemplate;

    private static final int MAX_RETRY_COUNT = 5;

    @RabbitListener(queues = RabbitMQConfig.BANK_ACCOUNT_QUEUE)
    public void consumeBankAccountEvent(BankAccountMessage message,
                                        @Header(AmqpHeaders.DELIVERY_TAG) long deliveryTag,
                                        Channel channel) {
        log.info("Received bank account creation event from RabbitMQ for userId: {}", message.getUserId());
        try {
            bankAccountRepository.saveBankAccount(
                            message.getUserId(),
                            message.getBankId(),
                            message.getAccountNumber(),
                            message.getAccountType(),
                            message.getAccountHolderName(),
                            message.getBalance(),
                            message.getCurrency(),
                            message.isPrimary(),
                            message.getCreatedBy())
                    .doOnSuccess(account ->
                            log.info("Bank account created via RabbitMQ for userId: {}, accountId: {}",
                                    message.getUserId(), account.getId())
                    )
                    .doOnError(e ->
                            log.error("Failed to create bank account from RabbitMQ event for userId: {}",
                                    message.getUserId(), e)
                    )
                    .block(); // blocking inside listener is acceptable

            channel.basicAck(deliveryTag, false);

        } catch (Exception e) {
            log.error("Error processing bank account event for userId: {}, retry count: {}",
                    message.getUserId(), message.getRetryCount(), e);
            handleRetryOrDeadLetter(message, deliveryTag, channel);
        }
    }

    private void handleRetryOrDeadLetter(BankAccountMessage message, long deliveryTag, Channel channel) {
        try {
            if (message.getRetryCount() < MAX_RETRY_COUNT) {
                message.setRetryCount(message.getRetryCount() + 1);
                log.warn("Retrying bank account creation via RabbitMQ, attempt {} for userId: {}",
                        message.getRetryCount(), message.getUserId());

                rabbitTemplate.convertAndSend(
                        RabbitMQConfig.BANK_ACCOUNT_EXCHANGE,
                        RabbitMQConfig.BANK_ACCOUNT_ROUTING_KEY,
                        message
                );
                channel.basicAck(deliveryTag, false); // ack original, re-queued manually
            } else {
                log.error("Max retries exceeded for userId: {}, sending to DLQ", message.getUserId());
                channel.basicNack(deliveryTag, false, false); // send to DLQ
            }
        } catch (IOException ioEx) {
            log.error("Failed to handle retry/DLQ for userId: {}", message.getUserId(), ioEx);
        }
    }
}
