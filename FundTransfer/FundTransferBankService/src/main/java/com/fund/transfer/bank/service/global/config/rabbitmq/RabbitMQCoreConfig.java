package com.fund.transfer.user.service.global.configure.rabbitmq;

import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Slf4j
@Configuration
public class RabbitMQCoreConfig {

    /**
     * JSON message converter for all RabbitMQ interactions.
     */
    @Bean
    public MessageConverter jsonMessageConverter() {
        return new Jackson2JsonMessageConverter();
    }

    /**
     * RabbitTemplate with publisher confirms, returns, and JSON converter.
     * <p>
     * Requires the following properties in your application.yml:
     *   spring.rabbitmq.publisher-confirm-type: correlated
     *   spring.rabbitmq.publisher-returns: true
     * </p>
     */
    @Bean
    public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
        RabbitTemplate template = new RabbitTemplate(connectionFactory);
        template.setMessageConverter(jsonMessageConverter());
        template.setMandatory(true); // enable returns

        // Handle returned messages (routing issues)
        template.setReturnsCallback(returned ->
                log.error("Message returned: exchange={}, routingKey={}, replyCode={}, replyText={}",
                        returned.getExchange(), returned.getRoutingKey(),
                        returned.getReplyCode(), returned.getReplyText())
        );

        // Handle publisher confirms
        template.setConfirmCallback((correlationData, ack, cause) -> {
            String id = correlationData != null ? correlationData.getId() : "unknown";
            if (ack) {
                log.info("Message confirmed by broker, correlationId: {}", id);
            } else {
                log.error("Message not confirmed, correlationId: {}, cause: {}", id, cause);
            }
        });

        return template;
    }
}