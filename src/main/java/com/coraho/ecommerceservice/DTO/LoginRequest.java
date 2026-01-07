package com.coraho.ecommerceservice.DTO;

import lombok.*;

@Data
public class LoginRequest {
    private String email;
    private String password;
}
