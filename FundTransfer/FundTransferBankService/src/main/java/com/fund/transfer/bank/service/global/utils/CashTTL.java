package com.fund.transfer.bank.service.global.utils;

import java.time.Duration;

public class CashTTL {

    public static final Duration LOGIN_CACHE_TTL = Duration.ofHours(6);
    public static final Duration AUTH_CACHE_TTL = Duration.ofHours(6);
    public static final Duration BANK_DETAILS_CACHE_TTL = Duration.ofHours(6);
    public static final Duration BANK_LIST_CACHE_TTL = Duration.ofMinutes(30);

}
