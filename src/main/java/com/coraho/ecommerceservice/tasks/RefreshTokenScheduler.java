package com.coraho.ecommerceservice.tasks;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.coraho.ecommerceservice.service.RefreshTokenService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenScheduler {
    private final RefreshTokenService refreshTokenService;

    @Scheduled(cron = "0 0 2 * * ?")
    public void cleanupExpiredTokens() {
        log.info("Starting cleanup of expired refresh token");
        int deletedCount = refreshTokenService.deleteExpiredTokens();
        log.info("Cleanu completed. Deleted {} expired tokens.", deletedCount);
    }

}
