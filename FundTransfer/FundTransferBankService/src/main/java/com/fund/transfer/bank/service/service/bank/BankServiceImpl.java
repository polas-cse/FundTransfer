package com.fund.transfer.bank.service.service.bank;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fund.transfer.bank.service.data.bank.BankRepository;
import com.fund.transfer.bank.service.global.exception.ApiException;
import com.fund.transfer.bank.service.global.security.JwtUtil;
import com.fund.transfer.bank.service.global.utils.CashKeyUtils;
import com.fund.transfer.bank.service.global.utils.CashTTL;
import com.fund.transfer.bank.service.shared.request.bank.BankListRequestDto;
import com.fund.transfer.bank.service.shared.request.bank.BankRequestDto;
import com.fund.transfer.bank.service.shared.response.bank.BankListResponseDto;
import com.fund.transfer.bank.service.shared.response.bank.BankResponseDto;
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
public class BankServiceImpl implements BankService{

    private static final Logger logger = LoggerFactory.getLogger(BankServiceImpl.class);
    private final ReactiveRedisTemplate<String, Object> redisTemplate;
    private final ModelMapper modelMapper;
    private final BankRepository bankRepository;
    private final ObjectMapper objectMapper;
    private final JwtUtil jwtUtil;

    // Cache key prefixes and patterns
    private final String AUTH_CACHE_PREFIX = CashKeyUtils.AUTH_CACHE_PREFIX;
    private final String BANK_DETAILS_CACHE_PREFIX = CashKeyUtils.BANK_DETAILS_CACHE_PREFIX;
    private final String BANK_LIST_CACHE_PREFIX = CashKeyUtils.BANK_LIST_CACHE_PREFIX;
    private final String BANK_LIST_CACHE_ALL = CashKeyUtils.BANK_LIST_CACHE_ALL;
    private final String BANK_LIST_CACHE_PATTERN = CashKeyUtils.BANK_LIST_CACHE_PATTERN;

    // Cache TTL durations
    private final Duration AUTH_CACHE_TTL = CashTTL.AUTH_CACHE_TTL;
    private final Duration BANK_DETAILS_CACHE_TTL = CashTTL.BANK_DETAILS_CACHE_TTL;
    private final Duration BANK_LIST_CACHE_TTL = CashTTL.BANK_LIST_CACHE_TTL;


    @Override
    public Mono<BankResponseDto> saveBank(String authHeader, BankRequestDto requestDto) {
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
                        bankRepository.saveBank(
                                        requestDto.getBankName(),
                                        requestDto.getBankCode(),
                                        requestDto.getSwiftCode(),
                                        requestDto.getCountry(),
                                        requestDto.getCapitalAmount(),
                                        requestDto.getTotalProfit(),
                                        requestDto.getTotalExpense(),
                                        userId)
                                .flatMap(entity -> {
                                    return redisTemplate.keys(BANK_LIST_CACHE_PATTERN)
                                            .collectList()
                                            .flatMap(keys -> {
                                                if (keys.isEmpty()) {
                                                    logger.info("No bank list caches found to delete From save bank");
                                                    return Mono.just(0L);
                                                }
                                                logger.info("Deleting {} bank list cache keys after save", keys.size());
                                                return redisTemplate.delete(keys.toArray(new String[0]))
                                                        .doOnNext(deleted ->
                                                                logger.info("Bank list caches deleted after save, count: {}", deleted)
                                                        );
                                            })
                                            .thenReturn(entity);
                                })
                )
                .map(entity -> BankResponseDto.builder()
                        .id(entity.getId())
                        .bankName(entity.getBankName())
                        .bankCode(entity.getBankCode())
                        .swiftCode(entity.getSwiftCode())
                        .country(entity.getCountry())
                        .capitalAmount(entity.getCapitalAmount())
                        .totalExpense(entity.getTotalExpense())
                        .active(entity.isActive())
                        .build()
                )
                .doOnSuccess(u -> {
                    if (u == null) {
                        logger.error("BankResponseDto is null!");
                    } else {
                        logger.info("Bank saved successfully: {}", u.getSwiftCode());
                    }
                })
                .onErrorMap(ex -> {
                    if (ex instanceof DuplicateKeyException duplicateEx) {
                        String message = duplicateEx.getMessage();
                        if (message.contains("bank_name")) {
                            return new ApiException("BANK_NAME_EXISTS", "Bank Name already exists");
                        }
                        if (message.contains("bank_code")) {
                            return new ApiException("BANK_CODE_EXISTS", "Bank Code already exists");
                        }
                        if (message.contains("swift_code")) {
                            return new ApiException("SWIFT_CODE_EXISTS", "Swift Code already exists");
                        }
                        return new ApiException("DUPLICATE_KEY", "Duplicate value found");
                    }
                    return ex;
                });
    }

    @Override
    public Mono<BankResponseDto> updateBank(String authHeader, BankRequestDto requestDto) {
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
                    String bankDetailsCacheKey = BANK_DETAILS_CACHE_PREFIX + requestDto.getId();
                    logger.info("Updating bank and clearing cache for key: {}", bankDetailsCacheKey);

                    return bankRepository.updateBank(
                                    requestDto.getId(),
                                    requestDto.getBankName(),
                                    requestDto.getBankCode(),
                                    requestDto.getSwiftCode(),
                                    requestDto.getCountry(),
                                    requestDto.getCapitalAmount(),
                                    requestDto.getTotalProfit(),
                                    requestDto.getTotalExpense(),
                                    requestDto.isActive(),
                                    userId)
                            .flatMap(entity -> {
                                Mono<Long> clearDetailsCache = redisTemplate.delete(bankDetailsCacheKey)
                                        .doOnNext(deleted ->
                                                logger.info("Bank details cache deleted after update: {}", deleted)
                                        );

                                Mono<Long> clearListCaches = redisTemplate.keys(BANK_LIST_CACHE_PATTERN)
                                        .collectList()
                                        .flatMap(keys -> {
                                            if (keys.isEmpty()) {
                                                logger.info("No bank list caches found to delete from update bank");
                                                return Mono.just(0L);
                                            }
                                            logger.info("Deleting {} user list cache keys after update", keys.size());
                                            return redisTemplate.delete(keys.toArray(new String[0]))
                                                    .doOnNext(deleted ->
                                                            logger.info("User list caches deleted after update, count: {}", deleted)
                                                    );
                                        });

                                return Mono.zip(clearDetailsCache, clearListCaches)
                                        .thenReturn(entity);
                            });
                })
                .map(entity -> BankResponseDto.builder()
                        .id(entity.getId())
                        .bankName(entity.getBankName())
                        .bankCode(entity.getBankCode())
                        .swiftCode(entity.getSwiftCode())
                        .country(entity.getCountry())
                        .capitalAmount(entity.getCapitalAmount())
                        .totalExpense(entity.getTotalExpense())
                        .active(entity.isActive())
                        .build()
                )
                .doOnSuccess(u -> {
                    if (u != null) {
                        logger.info("Bank updated successfully: {}", u.getBankName());
                    }
                })
                .onErrorMap(ex -> {
                    if (ex instanceof DuplicateKeyException duplicateEx) {
                        String message = duplicateEx.getMessage();
                        if (message.contains("bank_name")) {
                            return new ApiException("BANK_NAME_EXISTS", "Bank Name already exists");
                        }
                        if (message.contains("bank_code")) {
                            return new ApiException("BANK_CODE_EXISTS", "Bank Code already exists");
                        }
                        if (message.contains("swift_code")) {
                            return new ApiException("SWIFT_CODE_EXISTS", "Swift Code already exists");
                        }
                        return new ApiException("DUPLICATE_KEY", "Duplicate value found");
                    }
                    return ex;
                });

    }

    @Override
    public Mono<BankResponseDto> bankDetails(Long bankId) {

        String cacheKey = BANK_DETAILS_CACHE_PREFIX + bankId;
        logger.info("Checking cache for key: {}", cacheKey);

        return redisTemplate.opsForValue()
                .get(cacheKey)
                .doOnNext(data -> logger.info("Cache HIT for bankId: {}", bankId))
                .flatMap(cachedData -> {
                    try {
                        String jsonString = cachedData.toString();
                        logger.debug("Cached JSON data: {}", jsonString);

                        BankResponseDto dto = objectMapper.readValue(jsonString, BankResponseDto.class);
                        logger.info("Successfully deserialized bank from cache: {}", dto.getBankName());
                        return Mono.just(dto);
                    } catch (Exception e) {
                        logger.error("Error deserializing cached user details for BankId: {}", bankId, e);
                        return redisTemplate.delete(cacheKey).then(Mono.empty());
                    }
                })
                .switchIfEmpty(
                        Mono.defer(() -> {
                            logger.info("Cache MISS for bankId: {}, fetching from database", bankId);
                            return bankRepository.bankDetails(bankId)
                                    .flatMap(entity -> {
                                        logger.info("Bank Details fetched from Database for bankId: {}", bankId);

                                        BankResponseDto responseDto = BankResponseDto.builder()
                                                .id(entity.getId())
                                                .bankName(entity.getBankName())
                                                .bankCode(entity.getBankCode())
                                                .swiftCode(entity.getSwiftCode())
                                                .country(entity.getCountry())
                                                .capitalAmount(entity.getCapitalAmount())
                                                .totalExpense(entity.getTotalExpense())
                                                .active(entity.isActive())
                                                .createdByName(entity.getCreatedByName())
                                                .build();

                                        try {
                                            String jsonData = objectMapper.writeValueAsString(responseDto);
                                            logger.debug("Serialized JSON for caching: {}", jsonData);

                                            return redisTemplate.opsForValue()
                                                    .set(cacheKey, jsonData, BANK_DETAILS_CACHE_TTL)
                                                    .doOnSuccess(result ->
                                                            logger.info("Bank details cached successfully for bankId: {} with TTL 6 hours", bankId)
                                                    )
                                                    .doOnError(error ->
                                                            logger.error("Failed to cache bank details for bankId: {}", bankId, error)
                                                    )
                                                    .thenReturn(responseDto);
                                        } catch (Exception e) {
                                            logger.error("Error serializing bank details for caching, bankId: {}", bankId, e);
                                            return Mono.just(responseDto);
                                        }
                                    });
                        })
                )
                .doOnSuccess(dto -> {
                    if (dto != null) {
                        logger.info("Bank details retrieved successfully: {}", dto.getBankName());
                    } else {
                        logger.warn("Bank details not found for bankId: {}", bankId);
                    }
                })
                .doOnError(e -> logger.error("Error retrieving bank details for bankId: {}", bankId, e));

    }

    @Override
    public Flux<BankListResponseDto> bankList(BankListRequestDto requestDto) {
        String cacheKey = BANK_LIST_CACHE_PREFIX +
                (requestDto.getCreatedBy() != null ? "banks:" + requestDto.getCreatedBy() + ":" : "") +
                (requestDto.getSearch() != null && !requestDto.getSearch().isEmpty() ? "search:" + requestDto.getSearch() + ":" : "") +
                "limit:" + requestDto.getLimit() + ":offset:" + requestDto.getOffset();

        logger.info("Fetching bank list with cache key: {}", cacheKey);

        return redisTemplate.opsForValue()
                .get(cacheKey)
                .doOnNext(data -> logger.info("Cache HIT for bank list: {}", cacheKey))
                .flatMapMany(cachedData -> {
                    try {
                        String jsonString = cachedData.toString();
                        BankListResponseDto[] dtoArray = objectMapper.readValue(
                                jsonString,
                                BankListResponseDto[].class
                        );
                        logger.info("Successfully deserialized {} banks from cache", dtoArray.length);
                        return Flux.fromArray(dtoArray);
                    } catch (Exception e) {
                        logger.error("Error deserializing cached bank list", e);
                        return redisTemplate.delete(cacheKey).thenMany(Flux.empty());
                    }
                })
                .switchIfEmpty(
                        Flux.defer(() -> {
                            logger.info("Cache MISS for bank list, fetching from database");
                            return bankRepository.bankList(
                                            requestDto.getCreatedBy(),
                                            requestDto.getSearch(),
                                            requestDto.getLimit(),
                                            requestDto.getOffset()
                                    )
                                    .map(entity -> BankListResponseDto.builder()
                                            .id(entity.getId())
                                            .bankName(entity.getBankName())
                                            .bankCode(entity.getBankCode())
                                            .swiftCode(entity.getSwiftCode())
                                            .country(entity.getCountry())
                                            .capitalAmount(entity.getCapitalAmount())
                                            .totalExpense(entity.getTotalExpense())
                                            .active(entity.isActive())
                                            .build())
                                    .collectList()
                                    .flatMapMany(bankList -> {
                                        logger.info("Fetched {} banks from database", bankList.size());

                                        if (!bankList.isEmpty()) {
                                            try {
                                                String jsonData = objectMapper.writeValueAsString(bankList);
                                                return redisTemplate.opsForValue()
                                                        .set(cacheKey, jsonData, BANK_LIST_CACHE_TTL)
                                                        .doOnSuccess(result ->
                                                                logger.info("Bank list cached successfully with {} banks", bankList.size())
                                                        )
                                                        .thenMany(Flux.fromIterable(bankList));
                                            } catch (Exception e) {
                                                logger.error("Error serializing bank list for caching", e);
                                                return Flux.fromIterable(bankList);
                                            }
                                        }
                                        return Flux.fromIterable(bankList);
                                    });
                        })
                )
                .doOnComplete(() -> logger.info("Bank list retrieval completed"))
                .doOnError(e -> logger.error("Error retrieving bank list", e));
    }

    @Override
    public Mono<Long> bankCount(BankListRequestDto requestDto) {
        String countCacheKey = BANK_LIST_CACHE_PREFIX +
                (requestDto.getCreatedBy() != null ? "banks:" + requestDto.getCreatedBy() + ":" : "") +
                (requestDto.getSearch() != null && !requestDto.getSearch().isEmpty() ? "search:" + requestDto.getSearch() + ":" : "") +
                "limit:" + requestDto.getLimit() + ":offset:" + requestDto.getOffset() + ":count";

        return redisTemplate.opsForValue()
                .get(countCacheKey)
                .map(cached -> Long.parseLong(cached.toString()))
                .switchIfEmpty(
                        bankRepository.countBank(requestDto.getCreatedBy(), requestDto.getSearch())
                                .flatMap(count ->
                                        redisTemplate.opsForValue()
                                                .set(countCacheKey, count.toString(), BANK_LIST_CACHE_TTL)
                                                .thenReturn(count)
                                )
                );
    }

    @Override
    public Mono<BankResponseDto> deleteBank(Long bankId) {
        String bankDetailsCacheKey = BANK_DETAILS_CACHE_PREFIX + bankId;

        logger.info("Deleting bank with bankId: {}", bankId);

        return bankRepository.bankDelete(bankId)
                .flatMap(deletedBank -> {
                    logger.info("Bank soft-deleted successfully: {}", deletedBank.getId());

                    Mono<Long> deleteDetailsCache = redisTemplate.delete(bankDetailsCacheKey)
                            .doOnNext(deleted ->
                                    logger.info("Bank details cache deleted for bankId: {}, count: {}", bankId, deleted)
                            );

                    Mono<Long> deleteListCaches = redisTemplate.keys(BANK_LIST_CACHE_PATTERN)
                            .collectList()
                            .flatMap(keys -> {
                                if (keys.isEmpty()) {
                                    logger.info("No bank list caches found to delete");
                                    return Mono.just(0L);
                                }
                                logger.info("Deleting {} bank list cache keys after delete", keys.size());
                                return redisTemplate.delete(keys.toArray(new String[0]))
                                        .doOnNext(deleted ->
                                                logger.info("Bank list caches deleted after delete, count: {}", deleted)
                                        );
                            });

                    return Mono.zip(deleteDetailsCache, deleteListCaches)
                            .then(Mono.just(BankResponseDto.builder()
                                    .id(deletedBank.getId())
                                    .bankName(deletedBank.getBankName())
                                    .bankCode(deletedBank.getBankCode())
                                    .swiftCode(deletedBank.getSwiftCode())
                                    .country(deletedBank.getCountry())
                                    .capitalAmount(deletedBank.getCapitalAmount())
                                    .totalExpense(deletedBank.getTotalExpense())
                                    .active(deletedBank.isActive())
                                    .build()));
                })
                .doOnSuccess(dto -> {
                    if (dto != null) {
                        logger.info("Bank deleted successfully: {}", dto.getBankName());
                    }
                })
                .doOnError(e -> logger.error("Error deleting bank for bankId: {}", bankId, e));
    }
}
