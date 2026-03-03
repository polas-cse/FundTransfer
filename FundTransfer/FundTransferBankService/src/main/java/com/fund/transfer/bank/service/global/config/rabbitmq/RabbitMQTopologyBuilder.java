package com.fund.transfer.bank.service.global.config.rabbitmq;

import org.springframework.amqp.core.*;

public final class RabbitMQTopologyBuilder {

    private RabbitMQTopologyBuilder() {}

    public static Queue durableQueueWithDLQ(String queueName, String exchangeName, String dlqRoutingKey, long ttlMillis) {
        return QueueBuilder.durable(queueName)
                .withArgument("x-dead-letter-exchange", exchangeName)
                .withArgument("x-dead-letter-routing-key", dlqRoutingKey)
                .withArgument("x-message-ttl", ttlMillis)
                .build();
    }

    public static Queue durableDeadLetterQueue(String dlqName) {
        return QueueBuilder.durable(dlqName).build();
    }

    public static Binding bindQueueToExchange(Queue queue, TopicExchange exchange, String routingKey) {
        return BindingBuilder.bind(queue).to(exchange).with(routingKey);
    }
}