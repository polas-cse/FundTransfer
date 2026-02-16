package com.fund.transfer.bank.service.data.bank;

import com.fund.transfer.bank.service.data.bank.entity.Bank;
import io.lettuce.core.dynamic.annotation.Param;
import jakarta.annotation.Nullable;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface BankRepository extends R2dbcRepository<Bank, Long> {

    @Query("""
        INSERT INTO banking_service.banks(bank_name, bank_code, swift_code, country, capital_amount,
            total_profit, total_expense, active, created_by )
        VALUES (:bankName, :bankCode, :swiftCode, :country, :capitalAmount,
                :totalProfit, :totalExpense, :status, :createdBy )
        RETURNING *
        """)
    Mono<Bank> saveBank( String bankName, String bankCode, String swiftCode, String country,
            float capitalAmount, float totalProfit, float totalExpense, boolean status, Long createdBy );

    @Query("""
        UPDATE banking_service.banks
        SET bank_name = :bankName, bank_code = :bankCode, swift_code = :swiftCode, country = :country,
            capital_amount = :capitalAmount, total_profit = :totalProfit, total_expense = :totalExpense,
            active = :status, updated_by = :updatedBy, updated_at = NOW()
        WHERE id = :bankId
        RETURNING *
        """)
    Mono<Bank> updateBank( Long bankId, String bankName, String bankCode, String swiftCode, String country,
            float capitalAmount, float totalProfit, float totalExpense, boolean status, Long updatedBy );

    @Query("""
        SELECT  b.id, b.bank_name, b.bank_code, b.swift_code, b.country, b.capital_amount, b.total_profit,
            b.total_expense, b.active, CONCAT(u.first_name,' ',u.last_name) AS createdByName
        FROM banking_service.banks b
        LEFT JOIN user_service.users u  ON u.id = b.created_by
        WHERE b.id = :bankId AND b.active = true
        """)
    Mono<Bank> bankDetails(Long bankId);

    @Query("""
        UPDATE banking_service.banks SET active = false WHERE id = :bankId
        RETURNING *
        """)
    Mono<Bank> bankDelete(Long bankId);


    @Query("""
        SELECT  b.id, b.bank_name, b.bank_code, b.swift_code, b.country, b.capital_amount,
            b.total_profit, b.total_expense, b.active, b.created_by
        FROM banking_service.banks b
        WHERE b.active = true
        AND (:createdBy IS NULL OR b.created_by = :createdBy)
        AND (
            :search IS NULL OR
            LOWER(b.bank_name) LIKE LOWER(CONCAT('%', :search, '%')) OR
            LOWER(b.bank_code) LIKE LOWER(CONCAT('%', :search, '%')) OR
            LOWER(b.swift_code) LIKE LOWER(CONCAT('%', :search, '%')) OR
            LOWER(b.country) LIKE LOWER(CONCAT('%', :search, '%'))
        )
        ORDER BY b.created_at DESC
        LIMIT :limit OFFSET :offset
        """)
    Flux<Bank> bankList(@Nullable @Param("createdBy") Long createdBy, @Nullable @Param("search") String search,
            @Param("limit") Integer limit, @Param("offset") Integer offset );

    @Query("""
        SELECT COUNT(b.id) FROM banking_service.banks b WHERE b.active = true
        AND (:createdBy IS NULL OR b.created_by = :createdBy)
        AND (
            :search IS NULL OR
            LOWER(b.bank_name) LIKE LOWER(CONCAT('%', :search, '%')) OR
            LOWER(b.bank_code) LIKE LOWER(CONCAT('%', :search, '%')) OR
            LOWER(b.swift_code) LIKE LOWER(CONCAT('%', :search, '%')) OR
            LOWER(b.country) LIKE LOWER(CONCAT('%', :search, '%'))
        )
        """)
    Mono<Long> countBank(@Nullable @Param("createdBy") Long createdBy, @Nullable @Param("search") String search);

}