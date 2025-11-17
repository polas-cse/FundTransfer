package com.fund.transfer.api.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class FundTransferApiGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(FundTransferApiGatewayApplication.class, args);
	}

}
