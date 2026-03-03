package com.fund.transfer.bank.service.global.messaging.bankaccount.config;

import com.fund.transfer.bank.service.global.config.rabbitmq.RabbitMQCoreConfig;
import com.fund.transfer.bank.service.global.config.rabbitmq.RabbitMQTopologyBuilder;
import com.fund.transfer.bank.service.global.utils.RabbitMQUtils;
import org.springframework.amqp.core.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import(RabbitMQCoreConfig.class)
public class BankAccountServiceRabbitMQConfig {

    @Bean
    public TopicExchange bankAccountExchange() {
        return new TopicExchange(RabbitMQUtils.BANK_ACCOUNT_EXCHANGE, true, false);
    }

    @Bean
    public Queue bankAccountQueue() {
        return RabbitMQTopologyBuilder.durableQueueWithDLQ(
                RabbitMQUtils.BANK_ACCOUNT_QUEUE,
                RabbitMQUtils.BANK_ACCOUNT_EXCHANGE,
                RabbitMQUtils.BANK_ACCOUNT_DLQ_ROUTING,
                86400000
        );
    }

    @Bean
    public Queue bankAccountDeadLetterQueue() {
        return RabbitMQTopologyBuilder.durableDeadLetterQueue(RabbitMQUtils.BANK_ACCOUNT_DLQ);
    }

    @Bean
    public Binding bankAccountBinding() {
        return RabbitMQTopologyBuilder.bindQueueToExchange(
                bankAccountQueue(), bankAccountExchange(), RabbitMQUtils.BANK_ACCOUNT_ROUTING_KEY
        );
    }

    @Bean
    public Binding bankAccountDlqBinding() {
        return RabbitMQTopologyBuilder.bindQueueToExchange(
                bankAccountDeadLetterQueue(), bankAccountExchange(), RabbitMQUtils.BANK_ACCOUNT_DLQ_ROUTING
        );
    }
}