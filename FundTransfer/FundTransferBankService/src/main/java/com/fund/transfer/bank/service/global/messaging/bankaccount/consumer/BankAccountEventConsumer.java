package com.fund.transfer.bank.service.global.messaging.bankaccount.consumer;

import com.fund.transfer.bank.service.data.bankaccount.BankAccountRepository;
import com.fund.transfer.bank.service.global.messaging.bankaccount.model.BankAccountMessage;
import com.fund.transfer.bank.service.global.utils.RabbitMQUtils;
import com.rabbitmq.client.Channel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.AmqpHeaders;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class BankAccountEventConsumer {

    private final BankAccountRepository bankAccountRepository;
    private final RabbitTemplate rabbitTemplate;

    /// save bank account
    @RabbitListener(queues = RabbitMQUtils.BANK_ACCOUNT_CREATE_QUEUE)
    public void saveBankAccountConsume(BankAccountMessage message,
                        @Header(AmqpHeaders.DELIVERY_TAG) long deliveryTag,
                        Channel channel) throws IOException {
        log.info("Received event to save bank account for userId: {}", message.getUserId());
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
            log.error("Processing failed save bank account for userId: {}, retryCount: {}",
                    message.getUserId(), message.getRetryCount(), e);
            handleRetryOrDeadSaveBankAccountLetter(message, deliveryTag, channel);
        }
    }

    private void handleRetryOrDeadSaveBankAccountLetter(BankAccountMessage message, long deliveryTag, Channel channel) {
        try {
            if (message.getRetryCount() < RabbitMQUtils.MAX_RETRY_COUNT) {
                message.setRetryCount(message.getRetryCount() + 1);
                log.warn("Retrying (attempt {}) to save bank account for userId: {}", message.getRetryCount(), message.getUserId());

                rabbitTemplate.convertAndSend(
                        RabbitMQUtils.BANK_ACCOUNT_EXCHANGE,
                        RabbitMQUtils.BANK_ACCOUNT_ROUTING_CREATE_KEY,
                        message
                );
                channel.basicAck(deliveryTag, false);
            } else {
                log.error("Max retries exceeded to save bank account for userId: {}, sending to DLQ", message.getUserId());
                channel.basicNack(deliveryTag, false, false);
            }
        } catch (IOException e) {
            log.error("Failed to handle retry/DLQ to save bank account for userId: {}", message.getUserId(), e);
        }
    }

    /// update bank account
    @RabbitListener(queues = RabbitMQUtils.BANK_ACCOUNT_UPDATE_QUEUE,
            containerFactory = "batchRabbitListenerContainerFactory")
    public void updateBankAccountConsume(List<Message> rawMessages,
                                         Channel channel) throws IOException {
        log.info("Received batch update event, count: {}", rawMessages.size());

        List<BankAccountMessage> messages = rawMessages.stream()
                .map(msg -> (BankAccountMessage) rabbitTemplate.getMessageConverter().fromMessage(msg))
                .toList();

        try {
            Flux.fromIterable(messages)
                    .flatMap(message -> bankAccountRepository.updateBankAccount(
                            message.getId(),
                            message.getAccountNumber(),
                            message.getAccountType(),
                            message.getAccountHolderName(),
                            message.getBalance(),
                            message.getCurrency(),
                            message.isPrimary(),
                            message.getCreatedBy()
                    ), 10) // ✅ 10 concurrent DB updates
                    .collectList()
                    .block();

            long lastDeliveryTag = rawMessages.stream()
                    .mapToLong(msg -> (long) msg.getMessageProperties().getDeliveryTag())
                    .max()
                    .orElse(0L);
            channel.basicAck(lastDeliveryTag, true);
            log.info("Batch ack'd {} bank account updates", messages.size());

        } catch (Exception e) {
            log.error("Batch update failed, retryCount: {}", messages.get(0).getRetryCount(), e);
            handleBatchRetryOrDead(messages, rawMessages, channel);
        }
    }

    private void handleBatchRetryOrDead(List<BankAccountMessage> messages,
                                        List<Message> rawMessages,
                                        Channel channel) {
        try {
            long lastDeliveryTag = rawMessages.stream()
                    .mapToLong(msg -> (long) msg.getMessageProperties().getDeliveryTag())
                    .max()
                    .orElse(0L);

            boolean anyRetryable = messages.stream()
                    .anyMatch(m -> m.getRetryCount() < RabbitMQUtils.MAX_RETRY_COUNT);

            if (anyRetryable) {
                messages.forEach(message -> {
                    if (message.getRetryCount() < RabbitMQUtils.MAX_RETRY_COUNT) {
                        message.setRetryCount(message.getRetryCount() + 1);
                        log.warn("Retrying batch update (attempt {}) for userId: {}",
                                message.getRetryCount(), message.getUserId());
                        rabbitTemplate.convertAndSend(
                                RabbitMQUtils.BANK_ACCOUNT_EXCHANGE,
                                RabbitMQUtils.BANK_ACCOUNT_ROUTING_UPDATE_KEY,
                                message
                        );
                    }
                });
                channel.basicAck(lastDeliveryTag, true);
            } else {
                log.error("Max retries exceeded for batch, sending all to DLQ");
                channel.basicNack(lastDeliveryTag, true, false);
            }
        } catch (IOException e) {
            log.error("Failed to handle batch retry/DLQ", e);
        }
    }

}