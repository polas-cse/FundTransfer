package com.fund.transfer.user.service.global.messaging.bankaccount.config;


import com.fund.transfer.user.service.global.configure.rabbitmq.RabbitMQCoreConfig;
import com.fund.transfer.user.service.global.utils.RabbitMQUtils;
import org.springframework.amqp.core.TopicExchange;
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
}