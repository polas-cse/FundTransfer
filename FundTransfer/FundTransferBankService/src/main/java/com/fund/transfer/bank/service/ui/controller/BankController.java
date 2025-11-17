package com.fund.transfer.bank.service.ui.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("bank")
public class BankController {

    @GetMapping
    public String bankDetails(){
        return "Bank Details";
    }

}
