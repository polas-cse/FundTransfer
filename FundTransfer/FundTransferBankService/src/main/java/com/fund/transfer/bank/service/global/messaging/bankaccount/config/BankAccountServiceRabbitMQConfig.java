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

    /// Bank account create
    @Bean
    public Queue bankAccountCreateQueue() {
        return RabbitMQTopologyBuilder.durableQueueWithDLQ(
                RabbitMQUtils.BANK_ACCOUNT_CREATE_QUEUE,
                RabbitMQUtils.BANK_ACCOUNT_EXCHANGE,
                RabbitMQUtils.BANK_ACCOUNT_CREATE_DLQ_ROUTING,
                86400000
        );
    }

    @Bean
    public Queue bankAccountCreateDeadLetterQueue() {
        return RabbitMQTopologyBuilder.durableDeadLetterQueue(RabbitMQUtils.BANK_ACCOUNT_CREATE_DLQ);
    }

    @Bean
    public Binding bankAccountCreateBinding() {
        return RabbitMQTopologyBuilder.bindQueueToExchange(
                bankAccountCreateQueue(), bankAccountExchange(), RabbitMQUtils.BANK_ACCOUNT_ROUTING_CREATE_KEY
        );
    }

    @Bean
    public Binding bankAccountCreateDlqBinding() {
        return RabbitMQTopologyBuilder.bindQueueToExchange(
                bankAccountCreateDeadLetterQueue(), bankAccountExchange(), RabbitMQUtils.BANK_ACCOUNT_CREATE_DLQ_ROUTING
        );
    }


    /// Bank account update
    @Bean
    public Queue bankAccountUpdateQueue() {
        return RabbitMQTopologyBuilder.durableQueueWithDLQ(
                RabbitMQUtils.BANK_ACCOUNT_UPDATE_QUEUE,
                RabbitMQUtils.BANK_ACCOUNT_EXCHANGE,
                RabbitMQUtils.BANK_ACCOUNT_UPDATE_DLQ_ROUTING,
                86400000
        );
    }

    @Bean
    public Queue bankAccountUpdateDeadLetterQueue() {
        return RabbitMQTopologyBuilder.durableDeadLetterQueue(RabbitMQUtils.BANK_ACCOUNT_UPDATE_DLQ);
    }

    @Bean
    public Binding bankAccountUpdateBinding() {
        return RabbitMQTopologyBuilder.bindQueueToExchange(
                bankAccountUpdateQueue(), bankAccountExchange(), RabbitMQUtils.BANK_ACCOUNT_ROUTING_UPDATE_KEY
        );
    }

    @Bean
    public Binding bankAccountUpdateDlqBinding() {
        return RabbitMQTopologyBuilder.bindQueueToExchange(
                bankAccountUpdateDeadLetterQueue(), bankAccountExchange(), RabbitMQUtils.BANK_ACCOUNT_UPDATE_DLQ_ROUTING
        );
    }
}