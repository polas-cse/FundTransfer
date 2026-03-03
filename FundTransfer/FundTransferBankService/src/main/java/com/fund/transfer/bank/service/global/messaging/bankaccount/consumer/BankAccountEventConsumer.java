package com.fund.transfer.bank.service.global.messaging.bankaccount.consumer;

import com.fund.transfer.bank.service.data.bankaccount.BankAccountRepository;
import com.fund.transfer.bank.service.global.messaging.bankaccount.model.BankAccountMessage;
import com.fund.transfer.bank.service.global.utils.RabbitMQUtils;
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

    @RabbitListener(queues = RabbitMQUtils.BANK_ACCOUNT_QUEUE)
    public void consume(BankAccountMessage message,
                        @Header(AmqpHeaders.DELIVERY_TAG) long deliveryTag,
                        Channel channel) throws IOException {
        log.info("Received event for userId: {}", message.getUserId());
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
                    message.getCreatedBy()
            ).block();

            channel.basicAck(deliveryTag, false);
        } catch (Exception e) {
            log.error("Processing failed for userId: {}, retryCount: {}",
                    message.getUserId(), message.getRetryCount(), e);
            handleRetryOrDeadLetter(message, deliveryTag, channel);
        }
    }

    private void handleRetryOrDeadLetter(BankAccountMessage message, long deliveryTag, Channel channel) {
        try {
            if (message.getRetryCount() < RabbitMQUtils.MAX_RETRY_COUNT) {
                message.setRetryCount(message.getRetryCount() + 1);
                log.warn("Retrying (attempt {}) for userId: {}", message.getRetryCount(), message.getUserId());

                rabbitTemplate.convertAndSend(
                        RabbitMQUtils.BANK_ACCOUNT_EXCHANGE,
                        RabbitMQUtils.BANK_ACCOUNT_ROUTING_KEY,
                        message
                );
                channel.basicAck(deliveryTag, false);
            } else {
                log.error("Max retries exceeded for userId: {}, sending to DLQ", message.getUserId());
                channel.basicNack(deliveryTag, false, false);
            }
        } catch (IOException e) {
            log.error("Failed to handle retry/DLQ for userId: {}", message.getUserId(), e);
        }
    }
}