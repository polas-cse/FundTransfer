package com.fund.transfer.bank.service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class FundTransferBankServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(FundTransferBankServiceApplication.class, args);
	}

}
