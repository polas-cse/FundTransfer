package com.fund.transfer.user.service.global.configure;

import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.QueueBuilder;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
public class RabbitMQConfig {

    public static final String BANK_ACCOUNT_EXCHANGE       = "bank.account.exchange";
    public static final String BANK_ACCOUNT_QUEUE          = "bank.account.create.queue";
    public static final String BANK_ACCOUNT_ROUTING_KEY    = "bank.account.create";
    public static final String BANK_ACCOUNT_DLQ            = "bank.account.create.dlq";
    public static final String BANK_ACCOUNT_DLQ_ROUTING    = "bank.account.create.dead";

    @Bean
    public TopicExchange bankAccountExchange() {
        return new TopicExchange(BANK_ACCOUNT_EXCHANGE);
    }

    @Bean
    public Queue bankAccountQueue() {
        return QueueBuilder.durable(BANK_ACCOUNT_QUEUE)
                .withArgument("x-dead-letter-exchange", BANK_ACCOUNT_EXCHANGE)
                .withArgument("x-dead-letter-routing-key", BANK_ACCOUNT_DLQ_ROUTING)
                .withArgument("x-message-ttl", 60000)
                .build();
    }

    @Bean
    public Queue bankAccountDeadLetterQueue() {
        return QueueBuilder.durable(BANK_ACCOUNT_DLQ).build();
    }

    @Bean
    public Binding bankAccountBinding() {
        return BindingBuilder.bind(bankAccountQueue())
                .to(bankAccountExchange())
                .with(BANK_ACCOUNT_ROUTING_KEY);
    }

    @Bean
    public Binding bankAccountDlqBinding() {
        return BindingBuilder.bind(bankAccountDeadLetterQueue())
                .to(bankAccountExchange())
                .with(BANK_ACCOUNT_DLQ_ROUTING);
    }

    @Bean
    public MessageConverter jsonMessageConverter() {
        return new Jackson2JsonMessageConverter();
    }

    @Bean
    public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
        RabbitTemplate template = new RabbitTemplate(connectionFactory);
        template.setMessageConverter(jsonMessageConverter());
        return template;
    }
}