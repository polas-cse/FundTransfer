package com.fund.transfer.user.service.global.schema;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

@Slf4j
@Component("schemaInitializer") //named bean
public class SchemaInitializer implements InitializingBean { //NOT ApplicationRunner

    @Value("${spring.datasource.url}")
    private String jdbcUrl;

    @Value("${spring.datasource.username}")
    private String username;

    @Value("${spring.datasource.password}")
    private String password;

    @Value("${spring.liquibase.default-schema:user_service}")
    private String schemaName;

    @Override
    public void afterPropertiesSet() {
        log.info("╔══════════════════════════════════════════╗");
        log.info("║   User Service Schema Initialization...  ║");
        log.info("╚══════════════════════════════════════════╝");

        createSchemaIfNotExists();
    }

    private void createSchemaIfNotExists() {
        log.info("Checking schema '{}'...", schemaName);

        try (Connection conn = DriverManager.getConnection(
                jdbcUrl, username, password);
             Statement stmt = conn.createStatement()) {

            ResultSet rs = stmt.executeQuery(
                    "SELECT 1 FROM information_schema.schemata "
                            + "WHERE schema_name = '" + schemaName + "'");

            if (!rs.next()) {
                log.info("Schema '{}' not found — creating...", schemaName);

                stmt.executeUpdate(
                        "CREATE SCHEMA IF NOT EXISTS " + schemaName);

                stmt.executeUpdate(
                        "GRANT ALL PRIVILEGES ON SCHEMA "
                                + schemaName + " TO \"" + username + "\"");

                stmt.executeUpdate(
                        "ALTER DEFAULT PRIVILEGES IN SCHEMA " + schemaName
                                + " GRANT ALL PRIVILEGES ON TABLES TO \""
                                + username + "\"");

                stmt.executeUpdate(
                        "ALTER DEFAULT PRIVILEGES IN SCHEMA " + schemaName
                                + " GRANT ALL PRIVILEGES ON SEQUENCES TO \""
                                + username + "\"");

                log.info("Schema '{}' created successfully", schemaName);

            } else {
                log.info("Schema '{}' already exists — skipping", schemaName);
            }

        } catch (Exception e) {
            log.error("Schema init failed: {}", e.getMessage(), e);
            throw new RuntimeException(
                    "Failed to initialize schema: " + schemaName, e);
        }
    }
}