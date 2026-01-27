package com.coraho.ecommerceservice.tasks;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.coraho.ecommerceservice.service.EmailVerificationTokenService;
import com.coraho.ecommerceservice.service.LoginAttemptService;
import com.coraho.ecommerceservice.service.RefreshTokenService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class CleanupScheduler {
    private final RefreshTokenService refreshTokenService;
    private final EmailVerificationTokenService emailVerificationTokenService;
    private final LoginAttemptService loginAttemptService;

    @Scheduled(cron = "0 */5 * * * ?")
    public void cleanupExpiredRefreshTokens() {
        log.info("Starting scheduled cleanup of expired refresh token...");
        int deletedCount = refreshTokenService.deleteExpiredRefreshTokens();
        log.info("Cleanup completed. Deleted {} expired refresh tokens.", deletedCount);
    }

    @Scheduled(cron = "0 */5 * * * ?")
    public void cleanupExpiredEmailVerificationTokens() {
        log.info("Starting scheduled cleanup of expired Email verification token...");
        int deletedCount = emailVerificationTokenService.deleteExpiredEmailVerificationTokens();
        log.info("Cleanup completed. Deleted {} expired Email verification tokens", deletedCount);
    }

    @Scheduled(cron = "0 */5 * * * ?")
    public void cleanupOldLoginAttempts() {
        log.info("Starting scheduled cleanup of old login attempts...");
        long deletedCount = loginAttemptService.deleteOldAttempts();
        log.info("Cleanup completed. Deleted {} old login attempts", deletedCount);
    }
}
