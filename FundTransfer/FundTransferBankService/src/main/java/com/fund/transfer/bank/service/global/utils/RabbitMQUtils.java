package com.fund.transfer.bank.service.global.utils;

public class RabbitMQUtils {

    public static final int MAX_RETRY_COUNT = 5;

    public static final String BANK_ACCOUNT_EXCHANGE       = "bank.account.exchange";
    public static final String BANK_ACCOUNT_CREATE_QUEUE          = "bank.account.create.queue";
    public static final String BANK_ACCOUNT_ROUTING_CREATE_KEY    = "bank.account.create";
    public static final String BANK_ACCOUNT_CREATE_DLQ            = "bank.account.create.dlq";
    public static final String BANK_ACCOUNT_CREATE_DLQ_ROUTING    = "bank.account.create.dead";

    public static final String BANK_ACCOUNT_UPDATE_QUEUE          = "bank.account.update.queue";
    public static final String BANK_ACCOUNT_ROUTING_UPDATE_KEY    = "bank.account.update";
    public static final String BANK_ACCOUNT_UPDATE_DLQ            = "bank.account.update.dlq";
    public static final String BANK_ACCOUNT_UPDATE_DLQ_ROUTING    = "bank.account.update.dead";

    public static final String BANK_ACCOUNT_DETAILS_QUEUE          = "bank.account.details.queue";
    public static final String BANK_ACCOUNT_ROUTING_DETAILS_KEY    = "bank.account.details";
    public static final String BANK_ACCOUNT_DETAILS_DLQ            = "bank.account.details.dlq";
    public static final String BANK_ACCOUNT_DETAILS_DLQ_ROUTING    = "bank.account.details.dead";

}
