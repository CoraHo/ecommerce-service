package com.coraho.ecommerceservice.DTO;

import java.time.LocalDateTime;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class RegisterResponse {
    private Long id;
    private String email;
    private String username;
    private String firstName;
    private String lastName;
    private boolean isActive;
    private boolean isEmailVerified;
    private boolean isLocked;
    private LocalDateTime createdAt;
}
