package com.coraho.ecommerceservice.service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.coraho.ecommerceservice.entity.LoginAttempt;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.entity.LoginAttempt.AttemptResult;
import com.coraho.ecommerceservice.repository.LoginAttemptRepository;
import com.coraho.ecommerceservice.repository.UserRepository;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class LoginAttemptService {

    private final LoginAttemptRepository loginAttemptRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;

    @Value("${security.login.max-attempts:5}")
    private int maxFailedAttempts;

    @Value("${security.login.lockout-duration-munites:30}")
    private int lockoutDurationMunites;

    @Value("${security.login.attempt-window-munites:15}")
    private int attemptWindowMunites;

    @Value("${security.login.ip-max-attempts:10}")
    private int ipMaxAttempts;

    @Value("${security.login.suspicious-ip-threshold:5}")
    private int suspiciousIpThreshold;

    @Value("${security.login.suspicious-location-threshold:3}")
    private int suspiciousLocationThreshold;

    @Value("${security.login.attempt-retention-days:90}")
    private int attemptRententionDays;

    /* Record a login attempt */
    public void recordLoginAttempt(String email, String ipAddress, String userAgent, AttemptResult attemptResult,
            String failureReason) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        LoginAttempt loginAttempt = LoginAttempt.builder()
                .user(user)
                .email(email)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .attemptResult(attemptResult)
                .attemptedAt(LocalDateTime.now())
                .failureReason(failureReason)
                .build();

        loginAttemptRepository.save(loginAttempt);
        log.info("Login attempt recorded - Email: {}, IP: {}, Result: {}", email, ipAddress, attemptResult);
    }

    /* Handle successful login - reset countes and update last login */
    @Transactional
    public void handleSuccessfullogin(String email, String ipAddress) {
        Optional<User> userOpt = userRepository.findByEmail(email);

        if (userOpt.isEmpty()) {
            return;
        }

        User user = userOpt.get();

        user.setFailedLoginAttempts(0);
        user.setLastLoginAt(LocalDateTime.now());

        // unlock if it was locked
        if (Boolean.TRUE.equals(user.getIsLocked()) && user.getLockedUntil() != null) {
            user.setIsLocked(false);
            user.setLockedUntil(null);
            log.info("User account unlocked: {}", email);
        }

        // send a email to the use when new IP is detected
        boolean isNewIP = loginAttemptRepository.existsByUserIdAndIpAddressAndAttemptResult(user.getId(), ipAddress,
                AttemptResult.SUCCESS);
        if (!isNewIP) {
            emailService.sendNewIPLoggedInEmail(email, user.getFirstName(), ipAddress);
        }

        userRepository.save(user);
        log.info("Successful login attempt handled for user: {}", email);
    }

    /* Handle failed login - update counters and lock if needed */
    @Transactional
    public void handleFailedLogin(String email) {
        Optional<User> userOpt = userRepository.findByEmail(email);

        if (userOpt.isEmpty()) {
            return;
        }

        User user = userOpt.get();

        int failedLoginAttempt = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(failedLoginAttempt);

        // Lock account if failed login attempts exceeded
        if (failedLoginAttempt >= maxFailedAttempts) {
            user.setIsLocked(true);
            user.setLockedUntil(LocalDateTime.now().plusMinutes(lockoutDurationMunites));
            log.warn("Account locked due to excessive fialed attempts: {}", email);
        }

        userRepository.save(user);
    }

    /* Detect suspicious activity patterns */
    public boolean isSuspiciousActivity(String email, String ipAddress) {
        LocalDateTime since = LocalDateTime.now().minusMinutes(attemptWindowMunites);

        // Check for multiple different emails for same IP (credential stuffing)
        long distinctEmails = loginAttemptRepository.countDistinctEmailByIpAddressSince(ipAddress, since);
        if (distinctEmails >= suspiciousIpThreshold) {
            log.warn("Suspicious activity detected - Multiple emails from IP: {}", ipAddress);
            return true;
        }

        // Check for same email from multiple IPs (account takeover attempt)
        long distinctIps = loginAttemptRepository.countDistincIPAddressByEmailSince(email, since);
        if (distinctIps >= suspiciousLocationThreshold) {
            log.warn("Suspicious activity detected - Multiple IPs for email: {}", email);
            return true;
        }
        return false;
    }

    /* Check is user is locked */
    @Transactional
    public boolean isUserLocked(String email) {
        Optional<User> userOpt = userRepository.findByEmail(email);

        if (userOpt.isEmpty()) {
            return false;
        }
        User user = userOpt.get();

        // Check if user is manually locked
        if (Boolean.TRUE.equals(user.getIsLocked())) {
            if (user.getLockedUntil() != null && user.getLockedUntil().isBefore(LocalDateTime.now())) {
                // Unlock user
                user.setIsLocked(false);
                user.setLockedUntil(null);
                userRepository.save(user);
                log.info("User account unlocked: {}", email);
                return false;
            }
        }

        return true;

    }

    /* Check if the IP is blocked due to excessive attempts */
    public boolean isIpBlocked(String ipAddress) {
        LocalDateTime since = LocalDateTime.now().minusMinutes(attemptWindowMunites);
        long failedAttempts = loginAttemptRepository.countFailedLoginsByIpAddressAndSince(ipAddress, since);

        return failedAttempts >= ipMaxAttempts;
    }

    /* Get lockout remaining time for a user */
    public Optional<Duration> getLockoutRemaining(String email) {
        return userRepository.findByEmail(email)
                .filter(user -> Boolean.TRUE.equals(user.getIsLocked()))
                .map(User::getLockedUntil)
                .filter(lockedUntil -> lockedUntil.isAfter(LocalDateTime.now()))
                .map(lockedUntil -> Duration.between(LocalDateTime.now(), lockedUntil));
    }

    /* Cleanup old login attempts */
    public long deleteOldAttempts() {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(attemptRententionDays);
        List<LoginAttempt> oldLoginAttempts = loginAttemptRepository.findAll().stream()
                .filter(la -> la.getAttemptedAt().isBefore(cutoffDate))
                .toList();

        loginAttemptRepository.deleteAll(oldLoginAttempts);
        log.info("Cleaned up login attempts that are older than {} days", attemptRententionDays);
        return oldLoginAttempts.size();
    }
}
