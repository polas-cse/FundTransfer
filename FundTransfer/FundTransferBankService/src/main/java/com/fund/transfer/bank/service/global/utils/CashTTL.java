package com.fund.transfer.bank.service.global.utils;

import java.time.Duration;

public class CashTTL {

    //Cash ttl for login
    public static final Duration LOGIN_CACHE_TTL = Duration.ofHours(6);
    public static final Duration AUTH_CACHE_TTL = Duration.ofHours(6);

    //Cash ttl for bank
    public static final Duration BANK_DETAILS_CACHE_TTL = Duration.ofHours(6);
    public static final Duration BANK_LIST_CACHE_TTL = Duration.ofMinutes(30);

    //Cash ttl for bank
    public static final Duration BANK_ACCOUNT_DETAILS_CACHE_TTL = Duration.ofHours(6);
    public static final Duration BANK_ACCOUNT_LIST_CACHE_TTL = Duration.ofMinutes(30);

}
