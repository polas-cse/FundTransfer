package com.fund.transfer.user.service.global.schema;

import liquibase.integration.spring.SpringLiquibase;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;

@Slf4j
@Configuration
public class LiquibaseConfig {

    // read from liquibase specific properties
    @Value("${spring.liquibase.url}")
    private String url;

    @Value("${spring.liquibase.user}")
    private String username;

    @Value("${spring.liquibase.password}")
    private String password;

    @Value("${spring.liquibase.change-log}")
    private String changeLog;

    @Value("${spring.liquibase.default-schema:gateway_service}")
    private String defaultSchema;

    @Value("${spring.liquibase.liquibase-schema:gateway_service}")
    private String liquibaseSchema;

    @Value("${spring.liquibase.enabled:true}")
    private boolean enabled;

    // manually create JDBC DataSource — only used by Liquibase
    @Bean("liquibaseDataSource")
    public DataSource liquibaseDataSource() {
        DriverManagerDataSource ds = new DriverManagerDataSource();
        ds.setDriverClassName("org.postgresql.Driver");
        ds.setUrl(url);
        ds.setUsername(username);
        ds.setPassword(password);
        return ds;
    }

    // depends on schemaInitializer — schema created before Liquibase runs
    @Bean
    @DependsOn("schemaInitializer")
    public SpringLiquibase liquibase() {
        SpringLiquibase liquibase = new SpringLiquibase();
        liquibase.setDataSource(liquibaseDataSource()); // use our manual DataSource
        liquibase.setChangeLog(changeLog);
        liquibase.setDefaultSchema(defaultSchema);
        liquibase.setLiquibaseSchema(liquibaseSchema);
        liquibase.setShouldRun(enabled);
        log.info("Liquibase configured — schema: {}, changelog: {}",
                defaultSchema, changeLog);
        return liquibase;
    }
}