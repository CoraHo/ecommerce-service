package com.coraho.ecommerceservice.DTO;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthResponse {
    private String accessToken;
    private String refreshToken;
    private String username;
    private String email;
    private String sessionId;
    private String type = "Bearer";

}
