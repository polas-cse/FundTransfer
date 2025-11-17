package com.fund.transfer.user.service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class FundTransferUserServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(FundTransferUserServiceApplication.class, args);
	}

}
