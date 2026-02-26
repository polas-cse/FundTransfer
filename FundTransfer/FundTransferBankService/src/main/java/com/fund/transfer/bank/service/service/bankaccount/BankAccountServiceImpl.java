package com.fund.transfer.bank.service.service.bankaccount;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fund.transfer.bank.service.data.bankaccount.BankAccountRepository;
import com.fund.transfer.bank.service.global.exception.ApiException;
import com.fund.transfer.bank.service.global.security.JwtUtil;
import com.fund.transfer.bank.service.global.utils.CashKeyUtils;
import com.fund.transfer.bank.service.global.utils.CashTTL;
import com.fund.transfer.bank.service.shared.request.bankaccount.BankAccountListRequestDto;
import com.fund.transfer.bank.service.shared.request.bankaccount.BankAccountRequestDto;
import com.fund.transfer.bank.service.shared.response.bankaccount.BankAccountListResponseDto;
import com.fund.transfer.bank.service.shared.response.bankaccount.BankAccountResponseDto;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;


@Service
@RequiredArgsConstructor
public class BankAccountServiceImpl implements BankAccountService {

    private static final Logger logger = LoggerFactory.getLogger(BankAccountServiceImpl.class);
    private final ReactiveRedisTemplate<String, Object> redisTemplate;
    private final ModelMapper modelMapper;
    private final BankAccountRepository bankAccountRepository;
    private final ObjectMapper objectMapper;
    private final JwtUtil jwtUtil;

    // Cache key prefixes and patterns
    private final String AUTH_CACHE_PREFIX = CashKeyUtils.AUTH_CACHE_PREFIX;
    private final String BANK_ACCOUNT_DETAILS_CACHE_PREFIX = CashKeyUtils.BANK_ACCOUNT_DETAILS_CACHE_PREFIX;
    private final String BANK_ACCOUNT_LIST_CACHE_PREFIX = CashKeyUtils.BANK_ACCOUNT_LIST_CACHE_PREFIX;
    private final String BANK_ACCOUNT_LIST_CACHE_PATTERN = CashKeyUtils.BANK_ACCOUNT_LIST_CACHE_PATTERN;

    // Cache TTL durations
    private final Duration AUTH_CACHE_TTL = CashTTL.AUTH_CACHE_TTL;
    private final Duration BANK_ACCOUNT_DETAILS_CACHE_TTL = CashTTL.BANK_ACCOUNT_DETAILS_CACHE_TTL;
    private final Duration BANK_ACCOUNT_LIST_CACHE_TTL = CashTTL.BANK_ACCOUNT_LIST_CACHE_TTL;


    @Override
    public Mono<BankAccountResponseDto> saveBankAccount(String authHeader, BankAccountRequestDto requestDto) {
        String authCacheKey = AUTH_CACHE_PREFIX + authHeader;

        return redisTemplate.opsForValue()
                .get(authCacheKey)
                .map(idStr -> Long.parseLong(idStr.toString()))
                .doOnNext(id -> logger.info("UserId from Redis cache: {}", id))
                .switchIfEmpty(
                        jwtUtil.extractUserIdFromAuthHeader(authHeader)
                                .doOnNext(id -> logger.info("UserId from JWT: {}", id))
                                .flatMap(id ->
                                        redisTemplate.opsForValue()
                                                .set(authCacheKey, id.toString(), AUTH_CACHE_TTL)
                                                .thenReturn(id)
                                )
                )
                .flatMap(userId ->
                        bankAccountRepository.saveBankAccount(
                                        userId,
                                        requestDto.getBankId(),
                                        requestDto.getAccountNumber(),
                                        requestDto.getAccountType(),
                                        requestDto.getAccountHolderName(),
                                        requestDto.getBalance(),
                                        requestDto.getCurrency(),
                                        requestDto.isPrimary(),
                                        userId)
                                .flatMap(entity -> {
                                    return redisTemplate.keys(BANK_ACCOUNT_LIST_CACHE_PATTERN)
                                            .collectList()
                                            .flatMap(keys -> {
                                                if (keys.isEmpty()) {
                                                    logger.info("No bank account list caches found to delete from save bank account");
                                                    return Mono.just(0L);
                                                }
                                                logger.info("Deleting {} bank account list cache keys after save", keys.size());
                                                return redisTemplate.delete(keys.toArray(new String[0]))
                                                        .doOnNext(deleted ->
                                                                logger.info("Bank account list caches deleted after save, count: {}", deleted)
                                                        );
                                            })
                                            .thenReturn(entity);
                                })
                )
                .map(entity -> BankAccountResponseDto.builder()
                        .id(entity.getId())
                        .userId(entity.getUserId())
                        .bankId(entity.getBankId())
                        .accountNumber(entity.getAccountNumber())
                        .accountType(entity.getAccountType())
                        .accountHolderName(entity.getAccountHolderName())
                        .balance(entity.getBalance())
                        .currency(entity.getCurrency())
                        .isPrimary(entity.isPrimary())
                        .active(entity.isActive())
                        .build()
                )
                .doOnSuccess(dto -> {
                    if (dto == null) {
                        logger.error("BankAccountResponseDto is null!");
                    } else {
                        logger.info("Bank account saved successfully: {}", dto.getAccountNumber());
                    }
                })
                .onErrorMap(ex -> {
                    if (ex instanceof DuplicateKeyException duplicateEx) {
                        String message = duplicateEx.getMessage();
                        if (message.contains("account_number")) {
                            return new ApiException("ACCOUNT_NUMBER_EXISTS", "Account Number already exists");
                        }
                        return new ApiException("DUPLICATE_KEY", "Duplicate value found");
                    }
                    return ex;
                });
    }

    @Override
    public Mono<BankAccountResponseDto> updateBankAccount(String authHeader, BankAccountRequestDto requestDto) {
        String authCacheKey = AUTH_CACHE_PREFIX + authHeader;

        return redisTemplate.opsForValue()
                .get(authCacheKey)
                .map(idStr -> Long.parseLong(idStr.toString()))
                .doOnNext(id -> logger.info("UserId from Redis cache: {}", id))
                .switchIfEmpty(
                        jwtUtil.extractUserIdFromAuthHeader(authHeader)
                                .doOnNext(id -> logger.info("UserId from JWT: {}", id))
                                .flatMap(id ->
                                        redisTemplate.opsForValue()
                                                .set(authCacheKey, id.toString(), AUTH_CACHE_TTL)
                                                .thenReturn(id)
                                )
                )
                .flatMap(userId -> {
                    String bankAccountDetailsCacheKey = BANK_ACCOUNT_DETAILS_CACHE_PREFIX + requestDto.getId();
                    logger.info("Updating bank account and clearing cache for key: {}", bankAccountDetailsCacheKey);

                    return bankAccountRepository.updateBankAccount(
                                    requestDto.getId(),
                                    requestDto.getAccountNumber(),
                                    requestDto.getAccountType(),
                                    requestDto.getAccountHolderName(),
                                    requestDto.getBalance(),
                                    requestDto.getCurrency(),
                                    requestDto.isPrimary(),
                                    userId)
                            .flatMap(entity -> {
                                Mono<Long> clearDetailsCache = redisTemplate.delete(bankAccountDetailsCacheKey)
                                        .doOnNext(deleted ->
                                                logger.info("Bank account details cache deleted after update: {}", deleted)
                                        );

                                Mono<Long> clearListCaches = redisTemplate.keys(BANK_ACCOUNT_LIST_CACHE_PATTERN)
                                        .collectList()
                                        .flatMap(keys -> {
                                            if (keys.isEmpty()) {
                                                logger.info("No bank account list caches found to delete from update bank account");
                                                return Mono.just(0L);
                                            }
                                            logger.info("Deleting {} bank account list cache keys after update", keys.size());
                                            return redisTemplate.delete(keys.toArray(new String[0]))
                                                    .doOnNext(deleted ->
                                                            logger.info("Bank account list caches deleted after update, count: {}", deleted)
                                                    );
                                        });

                                return Mono.zip(clearDetailsCache, clearListCaches)
                                        .thenReturn(entity);
                            });
                })
                .map(entity -> BankAccountResponseDto.builder()
                        .id(entity.getId())
                        .userId(entity.getUserId())
                        .bankId(entity.getBankId())
                        .accountNumber(entity.getAccountNumber())
                        .accountType(entity.getAccountType())
                        .accountHolderName(entity.getAccountHolderName())
                        .balance(entity.getBalance())
                        .currency(entity.getCurrency())
                        .isPrimary(entity.isPrimary())
                        .active(entity.isActive())
                        .build()
                )
                .doOnSuccess(dto -> {
                    if (dto != null) {
                        logger.info("Bank account updated successfully: {}", dto.getAccountNumber());
                    }
                })
                .onErrorMap(ex -> {
                    if (ex instanceof DuplicateKeyException duplicateEx) {
                        String message = duplicateEx.getMessage();
                        if (message.contains("account_number")) {
                            return new ApiException("ACCOUNT_NUMBER_EXISTS", "Account Number already exists");
                        }
                        return new ApiException("DUPLICATE_KEY", "Duplicate value found");
                    }
                    return ex;
                });
    }

    @Override
    public Mono<BankAccountResponseDto> bankAccountDetails(Long bankAccountId) {
        String cacheKey = BANK_ACCOUNT_DETAILS_CACHE_PREFIX + bankAccountId;
        logger.info("Checking cache for key: {}", cacheKey);

        return redisTemplate.opsForValue()
                .get(cacheKey)
                .doOnNext(data -> logger.info("Cache HIT for bankAccountId: {}", bankAccountId))
                .flatMap(cachedData -> {
                    try {
                        String jsonString = cachedData.toString();
                        logger.debug("Cached JSON data: {}", jsonString);

                        BankAccountResponseDto dto = objectMapper.readValue(jsonString, BankAccountResponseDto.class);
                        logger.info("Successfully deserialized bank account from cache: {}", dto.getAccountNumber());
                        return Mono.just(dto);
                    } catch (Exception e) {
                        logger.error("Error deserializing cached bank account details for bankAccountId: {}", bankAccountId, e);
                        return redisTemplate.delete(cacheKey).then(Mono.empty());
                    }
                })
                .switchIfEmpty(
                        Mono.defer(() -> {
                            logger.info("Cache MISS for bankAccountId: {}, fetching from database", bankAccountId);
                            return bankAccountRepository.bankAccountDetails(bankAccountId)
                                    .flatMap(entity -> {
                                        logger.info("Bank Account Details fetched from Database for bankAccountId: {}", bankAccountId);

                                        BankAccountResponseDto responseDto = BankAccountResponseDto.builder()
                                                .id(entity.getId())
                                                .userId(entity.getUserId())
                                                .bankId(entity.getBankId())
                                                .accountNumber(entity.getAccountNumber())
                                                .accountType(entity.getAccountType())
                                                .accountHolderName(entity.getAccountHolderName())
                                                .balance(entity.getBalance())
                                                .currency(entity.getCurrency())
                                                .isPrimary(entity.isPrimary())
                                                .active(entity.isActive())
                                                .createdByName(entity.getCreatedByName())
                                                .build();

                                        try {
                                            String jsonData = objectMapper.writeValueAsString(responseDto);
                                            logger.debug("Serialized JSON for caching: {}", jsonData);

                                            return redisTemplate.opsForValue()
                                                    .set(cacheKey, jsonData, BANK_ACCOUNT_DETAILS_CACHE_TTL)
                                                    .doOnSuccess(result ->
                                                            logger.info("Bank account details cached successfully for bankAccountId: {}", bankAccountId)
                                                    )
                                                    .doOnError(error ->
                                                            logger.error("Failed to cache bank account details for bankAccountId: {}", bankAccountId, error)
                                                    )
                                                    .thenReturn(responseDto);
                                        } catch (Exception e) {
                                            logger.error("Error serializing bank account details for caching, bankAccountId: {}", bankAccountId, e);
                                            return Mono.just(responseDto);
                                        }
                                    });
                        })
                )
                .doOnSuccess(dto -> {
                    if (dto != null) {
                        logger.info("Bank account details retrieved successfully: {}", dto.getAccountNumber());
                    } else {
                        logger.warn("Bank account details not found for bankAccountId: {}", bankAccountId);
                    }
                })
                .doOnError(e -> logger.error("Error retrieving bank account details for bankAccountId: {}", bankAccountId, e));
    }

    @Override
    public Flux<BankAccountListResponseDto> bankAccountList(BankAccountListRequestDto requestDto) {
        String cacheKey = BANK_ACCOUNT_LIST_CACHE_PREFIX +
                (requestDto.getCreatedBy() != null ? "accounts:" + requestDto.getCreatedBy() + ":" : "") +
                (requestDto.getSearch() != null && !requestDto.getSearch().isEmpty() ? "search:" + requestDto.getSearch() + ":" : "") +
                "limit:" + requestDto.getLimit() + ":offset:" + requestDto.getOffset();

        logger.info("Fetching bank account list with cache key: {}", cacheKey);

        return redisTemplate.opsForValue()
                .get(cacheKey)
                .doOnNext(data -> logger.info("Cache HIT for bank account list: {}", cacheKey))
                .flatMapMany(cachedData -> {
                    try {
                        String jsonString = cachedData.toString();
                        BankAccountListResponseDto[] dtoArray = objectMapper.readValue(
                                jsonString,
                                BankAccountListResponseDto[].class
                        );
                        logger.info("Successfully deserialized {} bank accounts from cache", dtoArray.length);
                        return Flux.fromArray(dtoArray);
                    } catch (Exception e) {
                        logger.error("Error deserializing cached bank account list", e);
                        return redisTemplate.delete(cacheKey).thenMany(Flux.empty());
                    }
                })
                .switchIfEmpty(
                        Flux.defer(() -> {
                            logger.info("Cache MISS for bank account list, fetching from database");
                            return bankAccountRepository.bankAccountList(
                                            requestDto.getCreatedBy(),
                                            requestDto.getSearch(),
                                            requestDto.getLimit(),
                                            requestDto.getOffset()
                                    )
                                    .map(entity -> BankAccountListResponseDto.builder()
                                            .id(entity.getId())
                                            .userId(entity.getUserId())
                                            .bankId(entity.getBankId())
                                            .accountNumber(entity.getAccountNumber())
                                            .accountType(entity.getAccountType())
                                            .accountHolderName(entity.getAccountHolderName())
                                            .balance(entity.getBalance())
                                            .currency(entity.getCurrency())
                                            .isPrimary(entity.isPrimary())
                                            .active(entity.isActive())
                                            .build())
                                    .collectList()
                                    .flatMapMany(accountList -> {
                                        logger.info("Fetched {} bank accounts from database", accountList.size());

                                        if (!accountList.isEmpty()) {
                                            try {
                                                String jsonData = objectMapper.writeValueAsString(accountList);
                                                return redisTemplate.opsForValue()
                                                        .set(cacheKey, jsonData, BANK_ACCOUNT_LIST_CACHE_TTL)
                                                        .doOnSuccess(result ->
                                                                logger.info("Bank account list cached successfully with {} accounts", accountList.size())
                                                        )
                                                        .thenMany(Flux.fromIterable(accountList));
                                            } catch (Exception e) {
                                                logger.error("Error serializing bank account list for caching", e);
                                                return Flux.fromIterable(accountList);
                                            }
                                        }
                                        return Flux.fromIterable(accountList);
                                    });
                        })
                )
                .doOnComplete(() -> logger.info("Bank account list retrieval completed"))
                .doOnError(e -> logger.error("Error retrieving bank account list", e));
    }

    @Override
    public Mono<Long> bankAccountCount(BankAccountListRequestDto requestDto) {
        String countCacheKey = BANK_ACCOUNT_LIST_CACHE_PREFIX +
                (requestDto.getCreatedBy() != null ? "accounts:" + requestDto.getCreatedBy() + ":" : "") +
                (requestDto.getSearch() != null && !requestDto.getSearch().isEmpty() ? "search:" + requestDto.getSearch() + ":" : "") +
                "limit:" + requestDto.getLimit() + ":offset:" + requestDto.getOffset() + ":count";

        return redisTemplate.opsForValue()
                .get(countCacheKey)
                .map(cached -> Long.parseLong(cached.toString()))
                .switchIfEmpty(
                        bankAccountRepository.countBankAccount(requestDto.getCreatedBy(), requestDto.getSearch())
                                .flatMap(count ->
                                        redisTemplate.opsForValue()
                                                .set(countCacheKey, count.toString(), BANK_ACCOUNT_LIST_CACHE_TTL)
                                                .thenReturn(count)
                                )
                );
    }

    @Override
    public Mono<BankAccountResponseDto> deleteBankAccount(Long bankAccountId) {
        String bankAccountDetailsCacheKey = BANK_ACCOUNT_DETAILS_CACHE_PREFIX + bankAccountId;

        logger.info("Deleting bank account with bankAccountId: {}", bankAccountId);

        return bankAccountRepository.bankAccountDelete(bankAccountId)
                .flatMap(deletedAccount -> {
                    logger.info("Bank account soft-deleted successfully: {}", deletedAccount.getId());

                    Mono<Long> deleteDetailsCache = redisTemplate.delete(bankAccountDetailsCacheKey)
                            .doOnNext(deleted ->
                                    logger.info("Bank account details cache deleted for bankAccountId: {}, count: {}", bankAccountId, deleted)
                            );

                    Mono<Long> deleteListCaches = redisTemplate.keys(BANK_ACCOUNT_LIST_CACHE_PATTERN)
                            .collectList()
                            .flatMap(keys -> {
                                if (keys.isEmpty()) {
                                    logger.info("No bank account list caches found to delete");
                                    return Mono.just(0L);
                                }
                                logger.info("Deleting {} bank account list cache keys after delete", keys.size());
                                return redisTemplate.delete(keys.toArray(new String[0]))
                                        .doOnNext(deleted ->
                                                logger.info("Bank account list caches deleted after delete, count: {}", deleted)
                                        );
                            });

                    return Mono.zip(deleteDetailsCache, deleteListCaches)
                            .then(Mono.just(BankAccountResponseDto.builder()
                                    .id(deletedAccount.getId())
                                    .userId(deletedAccount.getUserId())
                                    .bankId(deletedAccount.getBankId())
                                    .accountNumber(deletedAccount.getAccountNumber())
                                    .accountType(deletedAccount.getAccountType())
                                    .accountHolderName(deletedAccount.getAccountHolderName())
                                    .balance(deletedAccount.getBalance())
                                    .currency(deletedAccount.getCurrency())
                                    .isPrimary(deletedAccount.isPrimary())
                                    .active(deletedAccount.isActive())
                                    .build()));
                })
                .doOnSuccess(dto -> {
                    if (dto != null) {
                        logger.info("Bank account deleted successfully: {}", dto.getAccountNumber());
                    }
                })
                .doOnError(e -> logger.error("Error deleting bank account for bankAccountId: {}", bankAccountId, e));
    }
}