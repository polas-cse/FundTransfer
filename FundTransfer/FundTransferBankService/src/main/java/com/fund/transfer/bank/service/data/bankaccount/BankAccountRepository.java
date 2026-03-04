package com.fund.transfer.bank.service.data.bankaccount;

import com.fund.transfer.bank.service.data.bankaccount.entity.BankAccount;
import io.lettuce.core.dynamic.annotation.Param;
import jakarta.annotation.Nullable;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface BankAccountRepository extends R2dbcRepository<BankAccount, Long> {

    @Query("""
        INSERT INTO banking_service.bank_accounts(user_id, bank_id, account_number, account_type, account_holder_name,
            balance, currency, is_primary, created_by)
        VALUES (:userId, :bankId, :accountNumber, :accountType, :accountHolderName,
                :balance, :currency, :isPrimary, :createdBy)
        RETURNING *
        """)
    Mono<BankAccount> saveBankAccount(long userId, long bankId, String accountNumber, String accountType,
                                      String accountHolderName, float balance, String currency,
                                      boolean isPrimary, long createdBy);

    @Query("""
        UPDATE banking_service.bank_accounts
        SET account_number = :accountNumber, account_type = :accountType,
            account_holder_name = :accountHolderName, balance = :balance,
            currency = :currency, is_primary = :isPrimary,
            updated_by = :updatedBy, updated_at = NOW()
        WHERE id = :bankAccountId
        RETURNING *
        """)
    Mono<BankAccount> updateBankAccount(long bankAccountId, String accountNumber, String accountType,
                                        String accountHolderName, float balance, String currency,
                                        boolean isPrimary, long updatedBy);

    @Query("""
        SELECT ba.id, ba.user_id, ba.bank_id, ba.account_number, ba.account_type,
            ba.account_holder_name, ba.balance, ba.currency, ba.is_primary, ba.active,
            CONCAT(u.first_name, ' ', u.last_name) AS created_by_name
        FROM banking_service.bank_accounts ba
        LEFT JOIN user_service.users u ON u.id = ba.created_by
        WHERE ba.id = :bankAccountId AND ba.active = true
        """)
    Mono<BankAccount> bankAccountDetails(long bankAccountId);

    @Query("""
        UPDATE banking_service.bank_accounts SET active = false WHERE id = :bankAccountId
        RETURNING *
        """)
    Mono<BankAccount> bankAccountDelete(long bankAccountId);

    @Query("""
        SELECT ba.id, ba.user_id, ba.bank_id, ba.account_number, ba.account_type,
            ba.account_holder_name, ba.balance, ba.currency, ba.is_primary,
            ba.active, ba.created_by
        FROM banking_service.bank_accounts ba
        WHERE ba.active = true
        AND (:createdBy IS NULL OR ba.created_by = :createdBy)
        AND (
            :search IS NULL OR
            LOWER(ba.account_number) LIKE LOWER(CONCAT('%', :search, '%')) OR
            LOWER(ba.account_type) LIKE LOWER(CONCAT('%', :search, '%')) OR
            LOWER(ba.account_holder_name) LIKE LOWER(CONCAT('%', :search, '%')) OR
            LOWER(ba.currency) LIKE LOWER(CONCAT('%', :search, '%'))
        )
        ORDER BY ba.created_at DESC
        LIMIT :limit OFFSET :offset
        """)
    Flux<BankAccount> bankAccountList(@Nullable @Param("createdBy") long createdBy,
                                      @Nullable @Param("search") String search,
                                      @Param("limit") Integer limit,
                                      @Param("offset") Integer offset);

    @Query("""
        SELECT COUNT(ba.id) FROM banking_service.bank_accounts ba WHERE ba.active = true
        AND (:createdBy IS NULL OR ba.created_by = :createdBy)
        AND (
            :search IS NULL OR
            LOWER(ba.account_number) LIKE LOWER(CONCAT('%', :search, '%')) OR
            LOWER(ba.account_type) LIKE LOWER(CONCAT('%', :search, '%')) OR
            LOWER(ba.account_holder_name) LIKE LOWER(CONCAT('%', :search, '%')) OR
            LOWER(ba.currency) LIKE LOWER(CONCAT('%', :search, '%'))
        )
        """)
    Mono<Long> countBankAccount(@Nullable @Param("createdBy") long createdBy,
                                @Nullable @Param("search") String search);

}