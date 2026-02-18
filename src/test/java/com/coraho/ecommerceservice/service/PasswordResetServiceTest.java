package com.coraho.ecommerceservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.util.*;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import com.coraho.ecommerceservice.DTO.PasswordResetRequest;
import com.coraho.ecommerceservice.DTO.ResetPasswordWithTokenRequest;
import com.coraho.ecommerceservice.entity.PasswordResetToken;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.exception.PasswordResetTokenException;
import com.coraho.ecommerceservice.repository.PasswordResetTokenRepository;
import com.coraho.ecommerceservice.repository.UserRepository;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@ExtendWith(MockitoExtension.class)
@DisplayName("PasswordResetService Tests")
public class PasswordResetServiceTest {

    @Mock
    private PasswordResetTokenRepository passwordResetTokenRepository;
    @Mock
    private EmailService emailService;
    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private SecurityContext securityContext;
    @Mock
    private Authentication authentication;
    @InjectMocks
    private PasswordResetService passwordResetService;

    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_FIRST_NAME = "John";
    private static final Long TEST_USER_ID = 1L;
    private static final String CURRENT_PASSWORD = "CurrentPass123";
    private static final String NEW_PASSWORD = "NewPass123";
    private static final String ENCODED_CURRENT_PASSWORD = "$2a$10$encodedCurrentPassword";
    private static final String ENCODED_NEW_PASSWORD = "$2a$10$encodedNewPassword";
    private static final String TEST_SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    private static final long TOKEN_EXPIRY_SECONDS = 3600L; // 1 hour
    private static final String EMAIL_BASE_URL = "http://localhost:8080";

    private User testUser;
    private String validToken;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(passwordResetService, "passwordResetTokenExpiryS", TOKEN_EXPIRY_SECONDS);
        ReflectionTestUtils.setField(passwordResetService, "passwordResetTokenSecretKey", TEST_SECRET_KEY);
        ReflectionTestUtils.setField(passwordResetService, "emailBaseUrl", EMAIL_BASE_URL);

        testUser = createTestUser();
        validToken = generateTestToken(TEST_EMAIL, TOKEN_EXPIRY_SECONDS);
        mockSecurityContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    // ===== resetPasswordWithCurrentPassword Tests =====

    @Test
    @DisplayName("Should reset password with current password successfully")
    void shouldResetPasswordWithCurrentPasswordSuccessfully() {
        // Given
        PasswordResetRequest request = PasswordResetRequest.builder()
                .currentPassword(CURRENT_PASSWORD)
                .newPassword(NEW_PASSWORD)
                .build();

        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(CURRENT_PASSWORD, ENCODED_CURRENT_PASSWORD)).thenReturn(true);
        when(passwordEncoder.matches(NEW_PASSWORD, ENCODED_CURRENT_PASSWORD)).thenReturn(false);
        when(passwordEncoder.encode(NEW_PASSWORD)).thenReturn(ENCODED_NEW_PASSWORD);
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        doNothing().when(emailService).sendPasswordResetConfirmationEmail(anyString(), anyString());

        // When
        passwordResetService.resetPasswordWithCurrentPassword(request);

        // Then
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        assertThat(userCaptor.getValue().getPasswordHash()).isEqualTo(ENCODED_NEW_PASSWORD);

        verify(passwordEncoder, times(1)).matches(CURRENT_PASSWORD, ENCODED_CURRENT_PASSWORD);
        verify(passwordEncoder, times(1)).encode(NEW_PASSWORD);
        verify(emailService, times(1)).sendPasswordResetConfirmationEmail(TEST_EMAIL, TEST_FIRST_NAME);
    }

    @Test
    @DisplayName("Should throw exception when current password is incorrect")
    void shouldThrowExceptionWhenCurrentPasswordIncorrect() {
        // Given
        PasswordResetRequest request = PasswordResetRequest.builder()
                .currentPassword("WrongPassword123")
                .newPassword(NEW_PASSWORD)
                .build();

        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("WrongPassword123", ENCODED_CURRENT_PASSWORD)).thenReturn(false);

        // When & Then
        assertThatThrownBy(() -> passwordResetService.resetPasswordWithCurrentPassword(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Password is incorrect");

        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any(User.class));
        verify(emailService, never()).sendPasswordResetConfirmationEmail(anyString(), anyString());
    }

    @Test
    @DisplayName("Should throw exception when user not authenticated")
    void shouldThrowExceptionWhenUserNotAuthenticated() {
        // Given
        when(authentication.isAuthenticated()).thenReturn(false);

        PasswordResetRequest request = PasswordResetRequest.builder()
                .currentPassword(CURRENT_PASSWORD)
                .newPassword(NEW_PASSWORD)
                .build();

        // When & Then
        assertThatThrownBy(() -> passwordResetService.resetPasswordWithCurrentPassword(request))
                .isInstanceOf(InsufficientAuthenticationException.class)
                .hasMessageContaining("User not logged in");
    }

    @Test
    @DisplayName("Should validate new password format")
    void shouldValidateNewPasswordFormat() {
        // Given
        PasswordResetRequest request = PasswordResetRequest.builder()
                .currentPassword(CURRENT_PASSWORD)
                .newPassword("weak") // Invalid: too short, no uppercase, no digit
                .build();

        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(CURRENT_PASSWORD, ENCODED_CURRENT_PASSWORD)).thenReturn(true);

        // When & Then
        assertThatThrownBy(() -> passwordResetService.resetPasswordWithCurrentPassword(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Password must be at least 6 characters");

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should throw exception when new password is same as current")
    void shouldThrowExceptionWhenNewPasswordSameAsCurrent() {
        // Given
        PasswordResetRequest request = PasswordResetRequest.builder()
                .currentPassword(CURRENT_PASSWORD)
                .newPassword(CURRENT_PASSWORD)
                .build();

        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(CURRENT_PASSWORD, ENCODED_CURRENT_PASSWORD)).thenReturn(true);
        when(passwordEncoder.matches(CURRENT_PASSWORD, ENCODED_CURRENT_PASSWORD)).thenReturn(true);

        // When & Then
        assertThatThrownBy(() -> passwordResetService.resetPasswordWithCurrentPassword(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("New password must be different from current password");

        verify(userRepository, never()).save(any(User.class));
    }

    // ===== forgotPassword Tests =====

    @Test
    @DisplayName("Should initiate forgot password flow successfully")
    void shouldInitiateForgotPasswordSuccessfully() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(passwordResetTokenRepository.findByUserIdAndIsUsedFalse(TEST_USER_ID))
                .thenReturn(new ArrayList<>());
        when(passwordResetTokenRepository.save(any(PasswordResetToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        doNothing().when(emailService).sendPasswordResetEmail(anyString(), anyString(), anyString());

        // When
        passwordResetService.forgotPassword(TEST_EMAIL);

        // Then
        verify(userRepository, times(1)).findByEmail(TEST_EMAIL);
        verify(passwordResetTokenRepository, times(1)).save(any(PasswordResetToken.class));
        verify(emailService, times(1)).sendPasswordResetEmail(eq(TEST_EMAIL), eq(TEST_FIRST_NAME), anyString());
    }

    @Test
    @DisplayName("Should throw UsernameNotFoundException when user not found")
    void shouldThrowExceptionWhenUserNotFoundForForgotPassword() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> passwordResetService.forgotPassword(TEST_EMAIL))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("User not found");

        verify(passwordResetTokenRepository, never()).save(any(PasswordResetToken.class));
        verify(emailService, never()).sendPasswordResetEmail(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("Should throw DisabledException when account is disabled")
    void shouldThrowExceptionWhenAccountDisabled() {
        // Given
        testUser.setIsActive(false);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        // When & Then
        assertThatThrownBy(() -> passwordResetService.forgotPassword(TEST_EMAIL))
                .isInstanceOf(DisabledException.class)
                .hasMessageContaining("Account is disabled");

        verify(passwordResetTokenRepository, never()).save(any(PasswordResetToken.class));
    }

    @Test
    @DisplayName("Should throw LockedException when account is locked")
    void shouldThrowExceptionWhenAccountLocked() {
        // Given
        testUser.setIsLocked(true);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        // When & Then
        assertThatThrownBy(() -> passwordResetService.forgotPassword(TEST_EMAIL))
                .isInstanceOf(LockedException.class)
                .hasMessageContaining("Account is locked");

        verify(passwordResetTokenRepository, never()).save(any(PasswordResetToken.class));
    }

    @Test
    @DisplayName("Should throw exception when requesting too soon after previous request")
    void shouldThrowExceptionWhenRequestingTooSoon() {
        // Given
        PasswordResetToken recentToken = createPasswordResetToken(
                LocalDateTime.now().plusMinutes(10), // Still valid and within cooldown
                false);

        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(passwordResetTokenRepository.findByUserIdAndIsUsedFalse(TEST_USER_ID))
                .thenReturn(List.of(recentToken));

        // When & Then
        assertThatThrownBy(() -> passwordResetService.forgotPassword(TEST_EMAIL))
                .isInstanceOf(PasswordResetTokenException.class)
                .hasMessageContaining("Please wait before requesting another password reset email");

        verify(passwordResetTokenRepository, never()).save(any(PasswordResetToken.class));
        verify(emailService, never()).sendPasswordResetEmail(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("Should invalidate existing unused tokens before creating new one")
    void shouldInvalidateExistingTokensBeforeCreatingNew() {
        // Given
        PasswordResetToken oldToken1 = createPasswordResetToken(LocalDateTime.now().plusMinutes(2), false);
        PasswordResetToken oldToken2 = createPasswordResetToken(LocalDateTime.now().plusMinutes(3), false);

        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(passwordResetTokenRepository.findByUserIdAndIsUsedFalse(TEST_USER_ID))
                .thenReturn(List.of(oldToken1, oldToken2));
        when(passwordResetTokenRepository.save(any(PasswordResetToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        doNothing().when(emailService).sendPasswordResetEmail(anyString(), anyString(), anyString());

        // When
        passwordResetService.forgotPassword(TEST_EMAIL);

        // Then
        verify(passwordResetTokenRepository, times(3)).save(any(PasswordResetToken.class)); // 2 old + 1 new
        assertThat(oldToken1.getIsUsed()).isTrue();
        assertThat(oldToken1.getUsedAt()).isNotNull();
        assertThat(oldToken2.getIsUsed()).isTrue();
        assertThat(oldToken2.getUsedAt()).isNotNull();
    }

    @Test
    @DisplayName("Should generate JWT token with correct claims")
    void shouldGenerateJwtTokenWithCorrectClaims() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(passwordResetTokenRepository.findByUserIdAndIsUsedFalse(TEST_USER_ID))
                .thenReturn(new ArrayList<>());
        when(passwordResetTokenRepository.save(any(PasswordResetToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        doNothing().when(emailService).sendPasswordResetEmail(anyString(), anyString(), anyString());

        // When
        passwordResetService.forgotPassword(TEST_EMAIL);

        // Then
        ArgumentCaptor<PasswordResetToken> tokenCaptor = ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(passwordResetTokenRepository).save(tokenCaptor.capture());

        String generatedToken = tokenCaptor.getValue().getToken();
        assertThat(generatedToken).isNotNull();

        // Verify JWT structure
        assertThat(generatedToken.split("\\.")).hasSize(3);

        // Parse and verify claims
        Claims claims = Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(TEST_SECRET_KEY)))
                .build()
                .parseSignedClaims(generatedToken)
                .getPayload();

        assertThat(claims.getSubject()).isEqualTo(TEST_EMAIL);
        assertThat(claims.get("Purpose")).isEqualTo("Reset Password");
        assertThat(claims.getIssuedAt()).isNotNull();
        assertThat(claims.getExpiration()).isNotNull();
    }

    @Test
    @DisplayName("Should send password reset email with correct link")
    void shouldSendPasswordResetEmailWithCorrectLink() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(passwordResetTokenRepository.findByUserIdAndIsUsedFalse(TEST_USER_ID))
                .thenReturn(new ArrayList<>());
        when(passwordResetTokenRepository.save(any(PasswordResetToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        doNothing().when(emailService).sendPasswordResetEmail(anyString(), anyString(), anyString());

        // When
        passwordResetService.forgotPassword(TEST_EMAIL);

        // Then
        ArgumentCaptor<String> linkCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailService).sendPasswordResetEmail(eq(TEST_EMAIL), eq(TEST_FIRST_NAME), linkCaptor.capture());

        String link = linkCaptor.getValue();
        assertThat(link).startsWith(EMAIL_BASE_URL + "/api/auth/validate-reset-password-token?token=");
    }

    // ===== validatePasswordResetToken Tests =====

    @Test
    @DisplayName("Should validate password reset token successfully")
    void shouldValidatePasswordResetTokenSuccessfully() {
        // Given
        PasswordResetToken token = createPasswordResetToken(LocalDateTime.now().plusHours(1), false);
        token.setToken(validToken);

        when(passwordResetTokenRepository.findByTokenAndIsUsedFalse(validToken))
                .thenReturn(Optional.of(token));
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        // When & Then
        assertThatCode(() -> passwordResetService.validatePasswordResetToken(validToken))
                .doesNotThrowAnyException();

        verify(passwordResetTokenRepository, times(1)).findByTokenAndIsUsedFalse(validToken);
    }

    @Test
    @DisplayName("Should throw exception when token not found in database")
    void shouldThrowExceptionWhenTokenNotFoundInDatabase() {
        // Given
        when(passwordResetTokenRepository.findByTokenAndIsUsedFalse(validToken))
                .thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> passwordResetService.validatePasswordResetToken(validToken))
                .isInstanceOf(PasswordResetTokenException.class)
                .hasMessageContaining("Password reset token not found");
    }

    @Test
    @DisplayName("Should throw exception when token is expired")
    void shouldThrowExceptionWhenTokenExpired() {
        // Given
        PasswordResetToken expiredToken = createPasswordResetToken(LocalDateTime.now().minusHours(1), false);
        expiredToken.setToken(validToken);

        when(passwordResetTokenRepository.findByTokenAndIsUsedFalse(validToken))
                .thenReturn(Optional.of(expiredToken));

        // When & Then
        assertThatThrownBy(() -> passwordResetService.validatePasswordResetToken(validToken))
                .isInstanceOf(PasswordResetTokenException.class)
                .hasMessageContaining("Password reset token has expired");
    }

    @Test
    @DisplayName("Should throw exception for invalid JWT signature")
    void shouldThrowExceptionForInvalidJwtSignature() {
        // Given
        String tamperedToken = validToken.substring(0, validToken.length() - 5) + "tampered";
        PasswordResetToken token = createPasswordResetToken(LocalDateTime.now().plusHours(1), false);
        token.setToken(tamperedToken);

        when(passwordResetTokenRepository.findByTokenAndIsUsedFalse(tamperedToken))
                .thenReturn(Optional.of(token));

        // When & Then
        assertThatThrownBy(() -> passwordResetService.validatePasswordResetToken(tamperedToken))
                .isInstanceOf(PasswordResetTokenException.class)
                .hasMessageContaining("Invalid password reset token");
    }

    @Test
    @DisplayName("Should throw exception when user from token not found")
    void shouldThrowExceptionWhenUserFromTokenNotFound() {
        // Given
        PasswordResetToken token = createPasswordResetToken(LocalDateTime.now().plusHours(1), false);
        token.setToken(validToken);

        when(passwordResetTokenRepository.findByTokenAndIsUsedFalse(validToken))
                .thenReturn(Optional.of(token));
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> passwordResetService.validatePasswordResetToken(validToken))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("User not found");
    }

    @Test
    @DisplayName("Should throw exception when user account is disabled during token validation")
    void shouldThrowExceptionWhenAccountDisabledDuringValidation() {
        // Given
        testUser.setIsActive(false);
        PasswordResetToken token = createPasswordResetToken(LocalDateTime.now().plusHours(1), false);
        token.setToken(validToken);

        when(passwordResetTokenRepository.findByTokenAndIsUsedFalse(validToken))
                .thenReturn(Optional.of(token));
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        // When & Then
        assertThatThrownBy(() -> passwordResetService.validatePasswordResetToken(validToken))
                .isInstanceOf(DisabledException.class)
                .hasMessageContaining("Account is disabled");
    }

    @Test
    @DisplayName("Should throw exception when user account is locked during token validation")
    void shouldThrowExceptionWhenAccountLockedDuringValidation() {
        // Given
        testUser.setIsLocked(true);
        PasswordResetToken token = createPasswordResetToken(LocalDateTime.now().plusHours(1), false);
        token.setToken(validToken);

        when(passwordResetTokenRepository.findByTokenAndIsUsedFalse(validToken))
                .thenReturn(Optional.of(token));
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        // When & Then
        assertThatThrownBy(() -> passwordResetService.validatePasswordResetToken(validToken))
                .isInstanceOf(LockedException.class)
                .hasMessageContaining("Account is locked");
    }

    // ===== resetPasswordWithToken Tests =====

    @Test
    @DisplayName("Should reset password with token successfully")
    void shouldResetPasswordWithTokenSuccessfully() {
        // Given
        ResetPasswordWithTokenRequest request = ResetPasswordWithTokenRequest.builder()
                .token(validToken)
                .newPassword(NEW_PASSWORD)
                .build();

        PasswordResetToken token = createPasswordResetToken(LocalDateTime.now().plusHours(1), false);
        token.setToken(validToken);

        when(passwordResetTokenRepository.findByTokenAndIsUsedFalse(validToken))
                .thenReturn(Optional.of(token));
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(NEW_PASSWORD, ENCODED_CURRENT_PASSWORD)).thenReturn(false);
        when(passwordEncoder.encode(NEW_PASSWORD)).thenReturn(ENCODED_NEW_PASSWORD);
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        when(passwordResetTokenRepository.save(any(PasswordResetToken.class))).thenReturn(token);
        doNothing().when(emailService).sendPasswordResetConfirmationEmail(anyString(), anyString());

        // When
        passwordResetService.resetPasswordWithToken(request);

        // Then
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        assertThat(userCaptor.getValue().getPasswordHash()).isEqualTo(ENCODED_NEW_PASSWORD);

        ArgumentCaptor<PasswordResetToken> tokenCaptor = ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(passwordResetTokenRepository, times(1)).save(tokenCaptor.capture());
        assertThat(tokenCaptor.getValue().getIsUsed()).isTrue();
        assertThat(tokenCaptor.getValue().getUsedAt()).isNotNull();
    }

    @Test
    @DisplayName("Should mark token as used after successful password reset")
    void shouldMarkTokenAsUsedAfterSuccessfulReset() {
        // Given
        ResetPasswordWithTokenRequest request = ResetPasswordWithTokenRequest.builder()
                .token(validToken)
                .newPassword(NEW_PASSWORD)
                .build();

        PasswordResetToken token = createPasswordResetToken(LocalDateTime.now().plusHours(1), false);
        token.setToken(validToken);

        when(passwordResetTokenRepository.findByTokenAndIsUsedFalse(validToken))
                .thenReturn(Optional.of(token));
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(NEW_PASSWORD, ENCODED_CURRENT_PASSWORD)).thenReturn(false);
        when(passwordEncoder.encode(NEW_PASSWORD)).thenReturn(ENCODED_NEW_PASSWORD);
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        when(passwordResetTokenRepository.save(any(PasswordResetToken.class))).thenReturn(token);
        doNothing().when(emailService).sendPasswordResetConfirmationEmail(anyString(), anyString());

        // When
        passwordResetService.resetPasswordWithToken(request);

        // Then
        ArgumentCaptor<PasswordResetToken> tokenCaptor = ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(passwordResetTokenRepository).save(tokenCaptor.capture());

        PasswordResetToken savedToken = tokenCaptor.getValue();
        assertThat(savedToken.getIsUsed()).isTrue();
        assertThat(savedToken.getUsedAt()).isBetween(
                LocalDateTime.now().minusSeconds(5),
                LocalDateTime.now().plusSeconds(5));
    }

    @Test
    @DisplayName("Should validate new password requirements when resetting with token")
    void shouldValidatePasswordRequirementsWhenResettingWithToken() {
        // Given
        ResetPasswordWithTokenRequest request = ResetPasswordWithTokenRequest.builder()
                .token(validToken)
                .newPassword("weak") // Invalid password
                .build();

        PasswordResetToken token = createPasswordResetToken(LocalDateTime.now().plusHours(1), false);
        token.setToken(validToken);

        when(passwordResetTokenRepository.findByTokenAndIsUsedFalse(validToken))
                .thenReturn(Optional.of(token));
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        // When & Then
        assertThatThrownBy(() -> passwordResetService.resetPasswordWithToken(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Password must be at least 6 characters");

        verify(userRepository, never()).save(any(User.class));
        verify(passwordResetTokenRepository, never()).save(any(PasswordResetToken.class));
    }

    @Test
    @DisplayName("Should send confirmation email after successful password reset")
    void shouldSendConfirmationEmailAfterReset() {
        // Given
        ResetPasswordWithTokenRequest request = ResetPasswordWithTokenRequest.builder()
                .token(validToken)
                .newPassword(NEW_PASSWORD)
                .build();

        PasswordResetToken token = createPasswordResetToken(LocalDateTime.now().plusHours(1), false);
        token.setToken(validToken);

        when(passwordResetTokenRepository.findByTokenAndIsUsedFalse(validToken))
                .thenReturn(Optional.of(token));
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(NEW_PASSWORD, ENCODED_CURRENT_PASSWORD)).thenReturn(false);
        when(passwordEncoder.encode(NEW_PASSWORD)).thenReturn(ENCODED_NEW_PASSWORD);
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        when(passwordResetTokenRepository.save(any(PasswordResetToken.class))).thenReturn(token);
        doNothing().when(emailService).sendPasswordResetConfirmationEmail(anyString(), anyString());

        // When
        passwordResetService.resetPasswordWithToken(request);

        // Then
        verify(emailService, times(1)).sendPasswordResetConfirmationEmail(TEST_EMAIL, TEST_FIRST_NAME);
    }

    @Test
    @DisplayName("Should not fail password reset if confirmation email fails")
    void shouldNotFailPasswordResetIfEmailFails() {
        // Given
        ResetPasswordWithTokenRequest request = ResetPasswordWithTokenRequest.builder()
                .token(validToken)
                .newPassword(NEW_PASSWORD)
                .build();

        PasswordResetToken token = createPasswordResetToken(LocalDateTime.now().plusHours(1), false);
        token.setToken(validToken);

        when(passwordResetTokenRepository.findByTokenAndIsUsedFalse(validToken))
                .thenReturn(Optional.of(token));
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(NEW_PASSWORD, ENCODED_CURRENT_PASSWORD)).thenReturn(false);
        when(passwordEncoder.encode(NEW_PASSWORD)).thenReturn(ENCODED_NEW_PASSWORD);
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        when(passwordResetTokenRepository.save(any(PasswordResetToken.class))).thenReturn(token);
        doThrow(new RuntimeException("Email service error"))
                .when(emailService).sendPasswordResetConfirmationEmail(anyString(), anyString());

        // When & Then
        assertThatCode(() -> passwordResetService.resetPasswordWithToken(request))
                .doesNotThrowAnyException();

        // Password should still be updated
        verify(userRepository, times(1)).save(any(User.class));
        verify(passwordResetTokenRepository, times(1)).save(any(PasswordResetToken.class));
    }

    @Test
    @DisplayName("Should throw exception when resetting with expired token")
    void shouldThrowExceptionWhenResettingWithExpiredToken() {
        // Given
        ResetPasswordWithTokenRequest request = ResetPasswordWithTokenRequest.builder()
                .token(validToken)
                .newPassword(NEW_PASSWORD)
                .build();

        PasswordResetToken expiredToken = createPasswordResetToken(LocalDateTime.now().minusHours(1), false);
        expiredToken.setToken(validToken);

        when(passwordResetTokenRepository.findByTokenAndIsUsedFalse(validToken))
                .thenReturn(Optional.of(expiredToken));

        // When & Then
        assertThatThrownBy(() -> passwordResetService.resetPasswordWithToken(request))
                .isInstanceOf(PasswordResetTokenException.class)
                .hasMessageContaining("Password reset token has expired");

        verify(userRepository, never()).save(any(User.class));
    }

    // ===== Helper Methods =====

    private User createTestUser() {
        User user = new User();
        user.setId(TEST_USER_ID);
        user.setEmail(TEST_EMAIL);
        user.setUsername("testuser");
        user.setFirstName(TEST_FIRST_NAME);
        user.setLastName("Doe");
        user.setPasswordHash(ENCODED_CURRENT_PASSWORD);
        user.setIsActive(true);
        user.setIsEmailVerified(true);
        user.setIsLocked(false);
        return user;
    }

    private PasswordResetToken createPasswordResetToken(LocalDateTime expiresAt, boolean isUsed) {
        PasswordResetToken token = new PasswordResetToken();
        token.setId(1L);
        token.setUser(testUser);
        token.setToken("some-token");
        token.setExpiresAt(expiresAt);
        token.setIsUsed(isUsed);
        if (isUsed) {
            token.setUsedAt(LocalDateTime.now().minusHours(1));
        }
        return token;
    }

    private String generateTestToken(String email, long expirySeconds) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(email)
                .claim("Purpose", "Reset Password")
                .issuedAt(new java.util.Date(now))
                .expiration(new java.util.Date(now + (expirySeconds * 1000)))
                .signWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(TEST_SECRET_KEY)))
                .compact();
    }

    private void mockSecurityContext() {
        lenient().when(authentication.isAuthenticated()).thenReturn(true);
        lenient().when(authentication.getName()).thenReturn(TEST_EMAIL);
        lenient().when(securityContext.getAuthentication()).thenReturn(authentication);
        SecurityContextHolder.setContext(securityContext);
    }

}
