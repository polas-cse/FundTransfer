package com.fund.transfer.discovery.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;

@SpringBootApplication
@EnableEurekaServer
public class FundTransferDiscoveryServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(FundTransferDiscoveryServerApplication.class, args);
	}

}
