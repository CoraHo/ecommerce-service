package com.coraho.ecommerceservice.DTO;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Data
@Builder
public class LoginRequest {
    @NotBlank(message = "Username or email is requied")
    private String usernameOrEmail;
    @NotBlank(message = "Password is requied")
    private String password;
}
