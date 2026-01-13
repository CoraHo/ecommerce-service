package com.coraho.ecommerceservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class EcommerceServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(EcommerceServiceApplication.class, args);
    }

}
