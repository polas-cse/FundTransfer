package com.fund.transfer.bank.service.global.messaging.bankaccount.config;

import com.fund.transfer.bank.service.global.config.rabbitmq.RabbitMQCoreConfig;
import com.fund.transfer.bank.service.global.utils.RabbitMQUtils;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import(RabbitMQCoreConfig.class)
public class UserServiceRabbitMQConfig {

    @Bean
    public TopicExchange bankAccountExchange() {
        return new TopicExchange(RabbitMQUtils.BANK_ACCOUNT_EXCHANGE, true, false);
    }
}