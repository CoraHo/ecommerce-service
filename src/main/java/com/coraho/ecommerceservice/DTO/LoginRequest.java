package com.coraho.ecommerceservice.DTO;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

@Data
public class LoginRequest {
    @NotBlank(message = "Username or email is requied")
    private String usernameOrEmail;
    @NotBlank(message = "Password is requied")
    @Size(min = 6, message = "Password must be at least 6 characters")
    private String password;
}
