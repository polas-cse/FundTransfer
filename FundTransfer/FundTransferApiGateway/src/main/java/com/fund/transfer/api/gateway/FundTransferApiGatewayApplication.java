package com.fund.transfer.api.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.liquibase.LiquibaseAutoConfiguration;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableDiscoveryClient
@EnableScheduling
@SpringBootApplication(
        exclude = {
                LiquibaseAutoConfiguration.class
        }
)
public class FundTransferApiGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(FundTransferApiGatewayApplication.class, args);
	}

}
