package com.fund.transfer.discovery.server.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

@Slf4j
@Component
@Order(1) // runs first before anything else
public class DatabaseInitializer implements ApplicationRunner {

    @Value("${db.superuser.url:jdbc:postgresql://localhost:5432/postgres}")
    private String superUrl;

    @Value("${db.superuser.username:postgres}")
    private String superUsername;

    @Value("${db.superuser.password:postgres}")
    private String superPassword;

    @Value("${db.app.name:fund-transfer}")
    private String dbName;

    @Value("${db.app.username:fund-transfer}")
    private String appUsername;

    @Value("${db.app.password:fund-transfer}")
    private String appPassword;

    @Override
    public void run(ApplicationArguments args) {
        log.info("╔══════════════════════════════════════════╗");
        log.info("║    Database Initialization Starting...   ║");
        log.info("╚══════════════════════════════════════════╝");

        createDatabaseIfNotExists();
        createUserIfNotExists();
        grantPrivileges();

        log.info("╔══════════════════════════════════════════╗");
        log.info("║    Database Initialization Complete      ║");
        log.info("╚══════════════════════════════════════════╝");
    }

    // ── Step 1: Create Database ───────────────────────────────────────
    private void createDatabaseIfNotExists() {
        log.info("Checking database '{}'...", dbName);

        try (Connection conn = DriverManager.getConnection(
                superUrl, superUsername, superPassword);
             Statement stmt = conn.createStatement()) {

            ResultSet rs = stmt.executeQuery(
                    "SELECT 1 FROM pg_database WHERE datname = '"
                            + dbName + "'");

            if (!rs.next()) {
                stmt.executeUpdate(
                        "CREATE DATABASE \"" + dbName + "\" "
                                + "WITH ENCODING='UTF8' "
                                + "LC_COLLATE='en_US.UTF-8' "
                                + "LC_CTYPE='en_US.UTF-8' "
                                + "TEMPLATE=template0");
                log.info("Database '{}' created successfully", dbName);
            } else {
                log.info("Database '{}' already exists — skipping", dbName);
            }

        } catch (Exception e) {
            log.error("Failed to create database '{}': {}",
                    dbName, e.getMessage());
        }
    }

    // ── Step 2: Create User ───────────────────────────────────────────

    private void createUserIfNotExists() {
        log.info("Checking user '{}'...", appUsername);

        try (Connection conn = DriverManager.getConnection(
                superUrl, superUsername, superPassword);
             Statement stmt = conn.createStatement()) {

            ResultSet rs = stmt.executeQuery(
                    "SELECT 1 FROM pg_roles WHERE rolname = '"
                            + appUsername + "'");

            if (!rs.next()) {
                stmt.executeUpdate(
                        "CREATE USER \"" + appUsername + "\" "
                                + "WITH PASSWORD '" + appPassword + "' "
                                + "CREATEDB"); // allow user to create schemas
                log.info("User '{}' created successfully", appUsername);
            } else {
                log.info("User '{}' already exists — skipping", appUsername);
            }

        } catch (Exception e) {
            log.error("Failed to create user '{}': {}",
                    appUsername, e.getMessage());
        }
    }

    // ── Step 3: Grant Privileges ──────────────────────────────────────

    private void grantPrivileges() {
        log.info("Granting privileges to user '{}'...", appUsername);

        // connect to app DB for grants
        String appDbUrl = "jdbc:postgresql://localhost:5432/" + dbName;

        try (Connection conn = DriverManager.getConnection(
                appDbUrl, superUsername, superPassword);
             Statement stmt = conn.createStatement()) {

            // grant DB access
            stmt.executeUpdate(
                    "GRANT ALL PRIVILEGES ON DATABASE \""
                            + dbName + "\" TO \"" + appUsername + "\"");

            // grant public schema access
            stmt.executeUpdate(
                    "GRANT ALL ON SCHEMA public TO \""
                            + appUsername + "\"");

            // set default search path
            stmt.executeUpdate(
                    "ALTER ROLE \"" + appUsername
                            + "\" SET search_path TO public");

            log.info("Privileges granted to '{}'", appUsername);

        } catch (Exception e) {
            log.error("Failed to grant privileges: {}", e.getMessage());
        }
    }
}