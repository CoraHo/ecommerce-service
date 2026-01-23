package com.coraho.ecommerceservice.DTO;

import java.time.Instant;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SessionInfo {
    private String sessionId;
    private Instant creationTime;
    private Instant lastAccessTime;
}
