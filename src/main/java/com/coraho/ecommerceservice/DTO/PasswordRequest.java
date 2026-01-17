package com.coraho.ecommerceservice.DTO;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class PasswordRequest {
    @NotNull(message = "Email is required")
    @Email(message = "Email should be valid")
    private String email;
}
