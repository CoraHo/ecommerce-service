package com.coraho.ecommerceservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.util.ReflectionTestUtils;

import com.coraho.ecommerceservice.entity.LoginAttempt;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.entity.LoginAttempt.AttemptResult;
import com.coraho.ecommerceservice.repository.LoginAttemptRepository;
import com.coraho.ecommerceservice.repository.UserRepository;

@ExtendWith(MockitoExtension.class)
@DisplayName("LoginAttemptService Tests")
public class LoginAttemptServiceTest {
    @Mock
    private LoginAttemptRepository loginAttemptRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private EmailService emailService;

    @InjectMocks
    private LoginAttemptService loginAttemptService;

    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_IP = "192.168.1.1";
    private static final String TEST_USER_AGENT = "Mozilla/5.0";
    private static final String TEST_FIRST_NAME = "John";
    private static final Long TEST_USER_ID = 1L;

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCKOUT_DURATION_MINUTES = 30;
    private static final int ATTEMPT_WINDOW_MINUTES = 15;
    private static final int IP_MAX_ATTEMPTS = 10;
    private static final int SUSPICIOUS_IP_THRESHOLD = 5;
    private static final int SUSPICIOUS_LOCATION_THRESHOLD = 3;
    private static final int ATTEMPT_RETENTION_DAYS = 90;

    private User testUser;

    @BeforeEach
    void setUp() {
        // Set @Value fields using ReflectionTestUtils
        ReflectionTestUtils.setField(loginAttemptService, "maxFailedAttempts", MAX_FAILED_ATTEMPTS);
        ReflectionTestUtils.setField(loginAttemptService, "lockoutDurationMunites", LOCKOUT_DURATION_MINUTES);
        ReflectionTestUtils.setField(loginAttemptService, "attemptWindowMunites", ATTEMPT_WINDOW_MINUTES);
        ReflectionTestUtils.setField(loginAttemptService, "ipMaxAttempts", IP_MAX_ATTEMPTS);
        ReflectionTestUtils.setField(loginAttemptService, "suspiciousIpThreshold", SUSPICIOUS_IP_THRESHOLD);
        ReflectionTestUtils.setField(loginAttemptService, "suspiciousLocationThreshold", SUSPICIOUS_LOCATION_THRESHOLD);
        ReflectionTestUtils.setField(loginAttemptService, "attemptRententionDays", ATTEMPT_RETENTION_DAYS);

        testUser = createTestUser();
    }

    // ===== recordLoginAttempt Tests =====

    @Test
    @DisplayName("Should record successful login attempt")
    void shouldRecordSuccessfulLoginAttempt() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(loginAttemptRepository.save(any(LoginAttempt.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // When
        loginAttemptService.recordLoginAttempt(TEST_EMAIL, TEST_IP, TEST_USER_AGENT,
                AttemptResult.SUCCESS, null);

        // Then
        ArgumentCaptor<LoginAttempt> attemptCaptor = ArgumentCaptor.forClass(LoginAttempt.class);
        verify(loginAttemptRepository).save(attemptCaptor.capture());

        LoginAttempt savedAttempt = attemptCaptor.getValue();
        assertThat(savedAttempt.getUser()).isEqualTo(testUser);
        assertThat(savedAttempt.getEmail()).isEqualTo(TEST_EMAIL);
        assertThat(savedAttempt.getIpAddress()).isEqualTo(TEST_IP);
        assertThat(savedAttempt.getUserAgent()).isEqualTo(TEST_USER_AGENT);
        assertThat(savedAttempt.getAttemptResult()).isEqualTo(AttemptResult.SUCCESS);
        assertThat(savedAttempt.getAttemptedAt()).isNotNull();
        assertThat(savedAttempt.getFailureReason()).isNull();
    }

    @Test
    @DisplayName("Should record failed login attempt with failure reason")
    void shouldRecordFailedLoginAttemptWithReason() {
        // Given
        String failureReason = "Invalid credentials";
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(loginAttemptRepository.save(any(LoginAttempt.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // When
        loginAttemptService.recordLoginAttempt(TEST_EMAIL, TEST_IP, TEST_USER_AGENT,
                AttemptResult.FAILED, failureReason);

        // Then
        ArgumentCaptor<LoginAttempt> attemptCaptor = ArgumentCaptor.forClass(LoginAttempt.class);
        verify(loginAttemptRepository).save(attemptCaptor.capture());

        LoginAttempt savedAttempt = attemptCaptor.getValue();
        assertThat(savedAttempt.getAttemptResult()).isEqualTo(AttemptResult.FAILED);
        assertThat(savedAttempt.getFailureReason()).isEqualTo(failureReason);
    }

    @Test
    @DisplayName("Should set attemptedAt timestamp when recording attempt")
    void shouldSetAttemptedAtTimestamp() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(loginAttemptRepository.save(any(LoginAttempt.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        LocalDateTime beforeAttempt = LocalDateTime.now();

        // When
        loginAttemptService.recordLoginAttempt(TEST_EMAIL, TEST_IP, TEST_USER_AGENT,
                AttemptResult.SUCCESS, null);

        // Then
        ArgumentCaptor<LoginAttempt> attemptCaptor = ArgumentCaptor.forClass(LoginAttempt.class);
        verify(loginAttemptRepository).save(attemptCaptor.capture());

        LocalDateTime attemptedAt = attemptCaptor.getValue().getAttemptedAt();
        assertThat(attemptedAt).isAfterOrEqualTo(beforeAttempt.minusSeconds(1));
        assertThat(attemptedAt).isBeforeOrEqualTo(LocalDateTime.now().plusSeconds(1));
    }

    @Test
    @DisplayName("Should throw UsernameNotFoundException when user not found")
    void shouldThrowExceptionWhenUserNotFoundForRecording() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> loginAttemptService.recordLoginAttempt(
                TEST_EMAIL, TEST_IP, TEST_USER_AGENT, AttemptResult.SUCCESS, null))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("User not found");

        verify(loginAttemptRepository, never()).save(any(LoginAttempt.class));
    }

    // ===== handleSuccessfullogin Tests =====

    @Test
    @DisplayName("Should reset failed login attempts on successful login")
    void shouldResetFailedLoginAttemptsOnSuccess() {
        // Given
        testUser.setFailedLoginAttempts(3);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(loginAttemptRepository.existsByUserIdAndIpAddressAndAttemptResult(
                TEST_USER_ID, TEST_IP, AttemptResult.SUCCESS)).thenReturn(true);
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        loginAttemptService.handleSuccessfullogin(TEST_EMAIL, TEST_IP);

        // Then
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());

        User savedUser = userCaptor.getValue();
        assertThat(savedUser.getFailedLoginAttempts()).isEqualTo(0);
    }

    @Test
    @DisplayName("Should update lastLoginAt timestamp on successful login")
    void shouldUpdateLastLoginAtTimestamp() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(loginAttemptRepository.existsByUserIdAndIpAddressAndAttemptResult(
                TEST_USER_ID, TEST_IP, AttemptResult.SUCCESS)).thenReturn(true);
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        LocalDateTime beforeLogin = LocalDateTime.now();

        // When
        loginAttemptService.handleSuccessfullogin(TEST_EMAIL, TEST_IP);

        // Then
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());

        LocalDateTime lastLoginAt = userCaptor.getValue().getLastLoginAt();
        assertThat(lastLoginAt).isAfterOrEqualTo(beforeLogin.minusSeconds(1));
        assertThat(lastLoginAt).isBeforeOrEqualTo(LocalDateTime.now().plusSeconds(1));
    }

    @Test
    @DisplayName("Should unlock user if locked with expiry time")
    void shouldUnlockUserIfLockedWithExpiry() {
        // Given
        testUser.setIsLocked(true);
        testUser.setLockedUntil(LocalDateTime.now().plusMinutes(10));

        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(loginAttemptRepository.existsByUserIdAndIpAddressAndAttemptResult(
                TEST_USER_ID, TEST_IP, AttemptResult.SUCCESS)).thenReturn(true);
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        loginAttemptService.handleSuccessfullogin(TEST_EMAIL, TEST_IP);

        // Then
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());

        User savedUser = userCaptor.getValue();
        assertThat(savedUser.getIsLocked()).isFalse();
        assertThat(savedUser.getLockedUntil()).isNull();
    }

    @Test
    @DisplayName("Should send email for new IP address")
    void shouldSendEmailForNewIpAddress() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(loginAttemptRepository.existsByUserIdAndIpAddressAndAttemptResult(
                TEST_USER_ID, TEST_IP, AttemptResult.SUCCESS)).thenReturn(false); // New IP
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        doNothing().when(emailService).sendNewIPLoggedInEmail(anyString(), anyString(), anyString());

        // When
        loginAttemptService.handleSuccessfullogin(TEST_EMAIL, TEST_IP);

        // Then
        verify(emailService, times(1)).sendNewIPLoggedInEmail(TEST_EMAIL, TEST_FIRST_NAME, TEST_IP);
    }

    @Test
    @DisplayName("Should not send email for known IP address")
    void shouldNotSendEmailForKnownIpAddress() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(loginAttemptRepository.existsByUserIdAndIpAddressAndAttemptResult(
                TEST_USER_ID, TEST_IP, AttemptResult.SUCCESS)).thenReturn(true); // Known IP
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        loginAttemptService.handleSuccessfullogin(TEST_EMAIL, TEST_IP);

        // Then
        verify(emailService, never()).sendNewIPLoggedInEmail(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("Should handle successful login gracefully when user not found")
    void shouldHandleSuccessfulLoginWhenUserNotFound() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());

        // When & Then
        assertThatCode(() -> loginAttemptService.handleSuccessfullogin(TEST_EMAIL, TEST_IP))
                .doesNotThrowAnyException();

        verify(userRepository, never()).save(any(User.class));
        verify(emailService, never()).sendNewIPLoggedInEmail(anyString(), anyString(), anyString());
    }

    // ===== handleFailedLogin Tests =====

    @Test
    @DisplayName("Should increment failed login attempts counter")
    void shouldIncrementFailedLoginAttempts() {
        // Given
        testUser.setFailedLoginAttempts(2);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        loginAttemptService.handleFailedLogin(TEST_EMAIL);

        // Then
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());

        assertThat(userCaptor.getValue().getFailedLoginAttempts()).isEqualTo(3);
    }

    @Test
    @DisplayName("Should lock account after max failed attempts")
    void shouldLockAccountAfterMaxFailedAttempts() {
        // Given
        testUser.setFailedLoginAttempts(MAX_FAILED_ATTEMPTS - 1); // One before max
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        LocalDateTime beforeLock = LocalDateTime.now();

        // When
        loginAttemptService.handleFailedLogin(TEST_EMAIL);

        // Then
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());

        User savedUser = userCaptor.getValue();
        assertThat(savedUser.getFailedLoginAttempts()).isEqualTo(MAX_FAILED_ATTEMPTS);
        assertThat(savedUser.getIsLocked()).isTrue();
        assertThat(savedUser.getLockedUntil()).isNotNull();
        assertThat(savedUser.getLockedUntil()).isAfter(beforeLock.plusMinutes(LOCKOUT_DURATION_MINUTES - 1));
        assertThat(savedUser.getLockedUntil()).isBefore(beforeLock.plusMinutes(LOCKOUT_DURATION_MINUTES + 1));
    }

    @Test
    @DisplayName("Should not lock account before reaching max attempts")
    void shouldNotLockAccountBeforeMaxAttempts() {
        // Given
        testUser.setFailedLoginAttempts(2);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        loginAttemptService.handleFailedLogin(TEST_EMAIL);

        // Then
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());

        User savedUser = userCaptor.getValue();
        assertThat(savedUser.getFailedLoginAttempts()).isEqualTo(3);
        assertThat(savedUser.getIsLocked()).isFalse();
        assertThat(savedUser.getLockedUntil()).isNull();
    }

    @Test
    @DisplayName("Should handle failed login gracefully when user not found")
    void shouldHandleFailedLoginWhenUserNotFound() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());

        // When & Then
        assertThatCode(() -> loginAttemptService.handleFailedLogin(TEST_EMAIL))
                .doesNotThrowAnyException();

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should lock account when already at max attempts")
    void shouldLockAccountWhenAlreadyAtMaxAttempts() {
        // Given
        testUser.setFailedLoginAttempts(MAX_FAILED_ATTEMPTS);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        loginAttemptService.handleFailedLogin(TEST_EMAIL);

        // Then
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());

        User savedUser = userCaptor.getValue();
        assertThat(savedUser.getFailedLoginAttempts()).isEqualTo(MAX_FAILED_ATTEMPTS + 1);
        assertThat(savedUser.getIsLocked()).isTrue();
    }

    // ===== isSuspiciousActivity Tests =====

    @Test
    @DisplayName("Should detect suspicious activity from multiple emails on same IP")
    void shouldDetectSuspiciousActivityMultipleEmailsSameIP() {
        // Given
        when(loginAttemptRepository.countDistinctEmailByIpAddressSince(eq(TEST_IP), any(LocalDateTime.class)))
                .thenReturn((long) SUSPICIOUS_IP_THRESHOLD);

        // When
        boolean isSuspicious = loginAttemptService.isSuspiciousActivity(TEST_EMAIL, TEST_IP);

        // Then
        assertThat(isSuspicious).isTrue();
        verify(loginAttemptRepository, times(1))
                .countDistinctEmailByIpAddressSince(eq(TEST_IP), any(LocalDateTime.class));
    }

    @Test
    @DisplayName("Should detect suspicious activity from same email on multiple IPs")
    void shouldDetectSuspiciousActivitySameEmailMultipleIPs() {
        // Given
        when(loginAttemptRepository.countDistinctEmailByIpAddressSince(eq(TEST_IP), any(LocalDateTime.class)))
                .thenReturn(2L);
        when(loginAttemptRepository.countDistincIPAddressByEmailSince(eq(TEST_EMAIL), any(LocalDateTime.class)))
                .thenReturn((long) SUSPICIOUS_LOCATION_THRESHOLD);

        // When
        boolean isSuspicious = loginAttemptService.isSuspiciousActivity(TEST_EMAIL, TEST_IP);

        // Then
        assertThat(isSuspicious).isTrue();
        verify(loginAttemptRepository, times(1))
                .countDistincIPAddressByEmailSince(eq(TEST_EMAIL), any(LocalDateTime.class));
    }

    @Test
    @DisplayName("Should not detect suspicious activity for normal patterns")
    void shouldNotDetectSuspiciousActivityForNormalPatterns() {
        // Given
        when(loginAttemptRepository.countDistinctEmailByIpAddressSince(eq(TEST_IP), any(LocalDateTime.class)))
                .thenReturn(2L);
        when(loginAttemptRepository.countDistincIPAddressByEmailSince(eq(TEST_EMAIL), any(LocalDateTime.class)))
                .thenReturn(1L);

        // When
        boolean isSuspicious = loginAttemptService.isSuspiciousActivity(TEST_EMAIL, TEST_IP);

        // Then
        assertThat(isSuspicious).isFalse();
    }

    @Test
    @DisplayName("Should check activity within time window")
    void shouldCheckActivityWithinTimeWindow() {
        // Given
        when(loginAttemptRepository.countDistinctEmailByIpAddressSince(eq(TEST_IP), any(LocalDateTime.class)))
                .thenReturn(2L);
        when(loginAttemptRepository.countDistincIPAddressByEmailSince(eq(TEST_EMAIL), any(LocalDateTime.class)))
                .thenReturn(1L);

        LocalDateTime expectedSince = LocalDateTime.now().minusMinutes(ATTEMPT_WINDOW_MINUTES);

        // When
        loginAttemptService.isSuspiciousActivity(TEST_EMAIL, TEST_IP);

        // Then
        ArgumentCaptor<LocalDateTime> sinceCaptor = ArgumentCaptor.forClass(LocalDateTime.class);
        verify(loginAttemptRepository).countDistinctEmailByIpAddressSince(eq(TEST_IP), sinceCaptor.capture());

        LocalDateTime actualSince = sinceCaptor.getValue();
        assertThat(actualSince).isBetween(
                expectedSince.minusSeconds(5),
                expectedSince.plusSeconds(5));
    }

    @Test
    @DisplayName("Should detect credential stuffing attack (multiple emails same IP)")
    void shouldDetectCredentialStuffingAttack() {
        // Given - Simulate 10 different emails from same IP
        when(loginAttemptRepository.countDistinctEmailByIpAddressSince(eq(TEST_IP), any(LocalDateTime.class)))
                .thenReturn(10L);

        // When
        boolean isSuspicious = loginAttemptService.isSuspiciousActivity(TEST_EMAIL, TEST_IP);

        // Then
        assertThat(isSuspicious).isTrue();
    }

    @Test
    @DisplayName("Should detect account takeover attempt (same email multiple IPs)")
    void shouldDetectAccountTakeoverAttempt() {
        // Given - Simulate same email from 5 different IPs
        when(loginAttemptRepository.countDistinctEmailByIpAddressSince(eq(TEST_IP), any(LocalDateTime.class)))
                .thenReturn(1L);
        when(loginAttemptRepository.countDistincIPAddressByEmailSince(eq(TEST_EMAIL), any(LocalDateTime.class)))
                .thenReturn(5L);

        // When
        boolean isSuspicious = loginAttemptService.isSuspiciousActivity(TEST_EMAIL, TEST_IP);

        // Then
        assertThat(isSuspicious).isTrue();
    }

    // ===== isUserLocked Tests =====

    @Test
    @DisplayName("Should return true when user not found")
    void shouldReturnTrueWhenUserNotFoundForLockCheck() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());

        // When
        boolean isLocked = loginAttemptService.isUserLocked(TEST_EMAIL);

        // Then
        assertThat(isLocked).isTrue();
    }

    @Test
    @DisplayName("Should return true when user is manually locked")
    void shouldReturnTrueWhenUserManuallyLocked() {
        // Given
        testUser.setIsLocked(true);
        testUser.setLockedUntil(null); // Manually locked (no expiry)
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        // When
        boolean isLocked = loginAttemptService.isUserLocked(TEST_EMAIL);

        // Then
        assertThat(isLocked).isTrue();
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should unlock user when temporary lock expired")
    void shouldUnlockUserWhenTemporaryLockExpired() {
        // Given
        testUser.setIsLocked(true);
        testUser.setLockedUntil(LocalDateTime.now().minusMinutes(5)); // Expired 5 minutes ago
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        boolean isLocked = loginAttemptService.isUserLocked(TEST_EMAIL);

        // Then
        assertThat(isLocked).isFalse();

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());

        User savedUser = userCaptor.getValue();
        assertThat(savedUser.getIsLocked()).isFalse();
        assertThat(savedUser.getLockedUntil()).isNull();
    }

    @Test
    @DisplayName("Should return true when temporary lock not yet expired")
    void shouldReturnTrueWhenTemporaryLockNotExpired() {
        // Given
        testUser.setIsLocked(true);
        testUser.setLockedUntil(LocalDateTime.now().plusMinutes(10));
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        // When
        boolean isLocked = loginAttemptService.isUserLocked(TEST_EMAIL);

        // Then
        assertThat(isLocked).isTrue();
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should return false when user is not locked")
    void shouldReturnFalseWhenUserNotLocked() {
        // Given
        testUser.setIsLocked(false);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        // When
        boolean isLocked = loginAttemptService.isUserLocked(TEST_EMAIL);

        // Then
        assertThat(isLocked).isFalse();
    }

    // ===== isIpBlocked Tests =====

    @Test
    @DisplayName("Should block IP after exceeding max attempts")
    void shouldBlockIpAfterExceedingMaxAttempts() {
        // Given
        when(loginAttemptRepository.countFailedLoginsByIpAddressAndSince(eq(TEST_IP), any(LocalDateTime.class)))
                .thenReturn((long) IP_MAX_ATTEMPTS);

        // When
        boolean isBlocked = loginAttemptService.isIpBlocked(TEST_IP);

        // Then
        assertThat(isBlocked).isTrue();
    }

    @Test
    @DisplayName("Should not block IP below max attempts")
    void shouldNotBlockIpBelowMaxAttempts() {
        // Given
        when(loginAttemptRepository.countFailedLoginsByIpAddressAndSince(eq(TEST_IP), any(LocalDateTime.class)))
                .thenReturn(5L);

        // When
        boolean isBlocked = loginAttemptService.isIpBlocked(TEST_IP);

        // Then
        assertThat(isBlocked).isFalse();
    }

    @Test
    @DisplayName("Should check IP attempts within time window")
    void shouldCheckIpAttemptsWithinTimeWindow() {
        // Given
        when(loginAttemptRepository.countFailedLoginsByIpAddressAndSince(eq(TEST_IP), any(LocalDateTime.class)))
                .thenReturn(5L);

        LocalDateTime expectedSince = LocalDateTime.now().minusMinutes(ATTEMPT_WINDOW_MINUTES);

        // When
        loginAttemptService.isIpBlocked(TEST_IP);

        // Then
        ArgumentCaptor<LocalDateTime> sinceCaptor = ArgumentCaptor.forClass(LocalDateTime.class);
        verify(loginAttemptRepository).countFailedLoginsByIpAddressAndSince(eq(TEST_IP), sinceCaptor.capture());

        LocalDateTime actualSince = sinceCaptor.getValue();
        assertThat(actualSince).isBetween(
                expectedSince.minusSeconds(5),
                expectedSince.plusSeconds(5));
    }

    @Test
    @DisplayName("Should not block IP with zero failed attempts")
    void shouldNotBlockIpWithZeroFailedAttempts() {
        // Given
        when(loginAttemptRepository.countFailedLoginsByIpAddressAndSince(eq(TEST_IP), any(LocalDateTime.class)))
                .thenReturn(0L);

        // When
        boolean isBlocked = loginAttemptService.isIpBlocked(TEST_IP);

        // Then
        assertThat(isBlocked).isFalse();
    }

    // ===== getLockoutRemaining Tests =====

    @Test
    @DisplayName("Should return remaining lockout duration")
    void shouldReturnRemainingLockoutDuration() {
        // Given
        LocalDateTime lockedUntil = LocalDateTime.now().plusMinutes(20);
        testUser.setIsLocked(true);
        testUser.setLockedUntil(lockedUntil);

        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        // When
        Optional<Duration> remaining = loginAttemptService.getLockoutRemaining(TEST_EMAIL);

        // Then
        assertThat(remaining).isPresent();
        assertThat(remaining.get().toMinutes()).isBetween(19L, 20L);
    }

    @Test
    @DisplayName("Should return empty when user not locked")
    void shouldReturnEmptyWhenUserNotLocked() {
        // Given
        testUser.setIsLocked(false);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        // When
        Optional<Duration> remaining = loginAttemptService.getLockoutRemaining(TEST_EMAIL);

        // Then
        assertThat(remaining).isEmpty();
    }

    @Test
    @DisplayName("Should return empty when lockout already expired")
    void shouldReturnEmptyWhenLockoutExpired() {
        // Given
        testUser.setIsLocked(true);
        testUser.setLockedUntil(LocalDateTime.now().minusMinutes(5));

        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        // When
        Optional<Duration> remaining = loginAttemptService.getLockoutRemaining(TEST_EMAIL);

        // Then
        assertThat(remaining).isEmpty();
    }

    @Test
    @DisplayName("Should return empty when user not found")
    void shouldReturnEmptyWhenUserNotFoundForLockout() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());

        // When
        Optional<Duration> remaining = loginAttemptService.getLockoutRemaining(TEST_EMAIL);

        // Then
        assertThat(remaining).isEmpty();
    }

    @Test
    @DisplayName("Should return empty when user locked but no lockedUntil set")
    void shouldReturnEmptyWhenLockedButNoExpirySet() {
        // Given
        testUser.setIsLocked(true);
        testUser.setLockedUntil(null); // Manually locked indefinitely

        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        // When
        Optional<Duration> remaining = loginAttemptService.getLockoutRemaining(TEST_EMAIL);

        // Then
        assertThat(remaining).isEmpty();
    }

    // ===== deleteOldAttempts Tests =====

    @Test
    @DisplayName("Should delete old login attempts successfully")
    void shouldDeleteOldLoginAttemptsSuccessfully() {
        // Given
        List<LoginAttempt> allAttempts = createLoginAttemptsList();
        when(loginAttemptRepository.findAll()).thenReturn(allAttempts);
        doNothing().when(loginAttemptRepository).deleteAll(anyList());

        // When
        long deletedCount = loginAttemptService.deleteOldAttempts();

        // Then
        assertThat(deletedCount).isEqualTo(2); // 2 old attempts in list

        ArgumentCaptor<List<LoginAttempt>> attemptsCaptor = ArgumentCaptor.forClass(List.class);
        verify(loginAttemptRepository).deleteAll(attemptsCaptor.capture());

        List<LoginAttempt> deletedAttempts = attemptsCaptor.getValue();
        assertThat(deletedAttempts).hasSize(2);
        assertThat(deletedAttempts).allMatch(
                attempt -> attempt.getAttemptedAt().isBefore(LocalDateTime.now().minusDays(ATTEMPT_RETENTION_DAYS)));
    }

    @Test
    @DisplayName("Should return zero when no old attempts to delete")
    void shouldReturnZeroWhenNoOldAttempts() {
        // Given
        List<LoginAttempt> recentAttempts = List.of(
                createLoginAttempt(LocalDateTime.now().minusDays(10)),
                createLoginAttempt(LocalDateTime.now().minusDays(20)));
        when(loginAttemptRepository.findAll()).thenReturn(recentAttempts);
        doNothing().when(loginAttemptRepository).deleteAll(anyList());

        // When
        long deletedCount = loginAttemptService.deleteOldAttempts();

        // Then
        assertThat(deletedCount).isEqualTo(0);

        ArgumentCaptor<List<LoginAttempt>> attemptsCaptor = ArgumentCaptor.forClass(List.class);
        verify(loginAttemptRepository).deleteAll(attemptsCaptor.capture());
        assertThat(attemptsCaptor.getValue()).isEmpty();
    }

    @Test
    @DisplayName("Should handle empty attempts list")
    void shouldHandleEmptyAttemptsList() {
        // Given
        when(loginAttemptRepository.findAll()).thenReturn(new ArrayList<>());
        doNothing().when(loginAttemptRepository).deleteAll(anyList());

        // When
        long deletedCount = loginAttemptService.deleteOldAttempts();

        // Then
        assertThat(deletedCount).isEqualTo(0);
        verify(loginAttemptRepository, times(1)).findAll();
        verify(loginAttemptRepository, times(1)).deleteAll(anyList());
    }

    @Test
    @DisplayName("Should use correct retention period for deletion")
    void shouldUseCorrectRetentionPeriod() {
        // Given
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(ATTEMPT_RETENTION_DAYS);
        List<LoginAttempt> attempts = List.of(
                createLoginAttempt(cutoffDate.minusDays(1)), // Should be deleted
                createLoginAttempt(cutoffDate.plusDays(1)) // Should be kept
        );

        when(loginAttemptRepository.findAll()).thenReturn(attempts);
        doNothing().when(loginAttemptRepository).deleteAll(anyList());

        // When
        long deletedCount = loginAttemptService.deleteOldAttempts();

        // Then
        assertThat(deletedCount).isEqualTo(1);

        ArgumentCaptor<List<LoginAttempt>> attemptsCaptor = ArgumentCaptor.forClass(List.class);
        verify(loginAttemptRepository).deleteAll(attemptsCaptor.capture());

        List<LoginAttempt> deletedAttempts = attemptsCaptor.getValue();
        assertThat(deletedAttempts).hasSize(1);
        assertThat(deletedAttempts.get(0).getAttemptedAt()).isBefore(cutoffDate);
    }

    // ===== Helper Methods =====

    private User createTestUser() {
        User user = new User();
        user.setId(TEST_USER_ID);
        user.setEmail(TEST_EMAIL);
        user.setUsername("testuser");
        user.setFirstName(TEST_FIRST_NAME);
        user.setLastName("Doe");
        user.setIsActive(true);
        user.setIsEmailVerified(true);
        user.setIsLocked(false);
        user.setFailedLoginAttempts(0);
        return user;
    }

    private LoginAttempt createLoginAttempt(LocalDateTime attemptedAt) {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setId(1L);
        attempt.setUser(testUser);
        attempt.setEmail(TEST_EMAIL);
        attempt.setIpAddress(TEST_IP);
        attempt.setUserAgent(TEST_USER_AGENT);
        attempt.setAttemptResult(AttemptResult.SUCCESS);
        attempt.setAttemptedAt(attemptedAt);
        return attempt;
    }

    private List<LoginAttempt> createLoginAttemptsList() {
        List<LoginAttempt> attempts = new ArrayList<>();

        // Recent attempts (should be kept)
        attempts.add(createLoginAttempt(LocalDateTime.now().minusDays(10)));
        attempts.add(createLoginAttempt(LocalDateTime.now().minusDays(20)));

        // Old attempts (should be deleted)
        attempts.add(createLoginAttempt(LocalDateTime.now().minusDays(ATTEMPT_RETENTION_DAYS + 1)));
        attempts.add(createLoginAttempt(LocalDateTime.now().minusDays(ATTEMPT_RETENTION_DAYS + 10)));

        return attempts;
    }
}
