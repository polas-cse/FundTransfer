package com.fund.transfer.bank.service.global.utils;

public class RabbitMQUtils {

    public static final String BANK_ACCOUNT_EXCHANGE       = "bank.account.exchange";
    public static final String BANK_ACCOUNT_QUEUE          = "bank.account.create.queue";
    public static final String BANK_ACCOUNT_ROUTING_KEY    = "bank.account.create";
    public static final String BANK_ACCOUNT_DLQ            = "bank.account.create.dlq";
    public static final String BANK_ACCOUNT_DLQ_ROUTING    = "bank.account.create.dead";

}
