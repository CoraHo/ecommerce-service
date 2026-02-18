package com.coraho.ecommerceservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
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
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.util.ReflectionTestUtils;

import com.coraho.ecommerceservice.entity.EmailVerificationToken;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.exception.EmailVerificationException;
import com.coraho.ecommerceservice.repository.EmailVerificationTokenRepository;
import com.coraho.ecommerceservice.repository.UserRepository;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@ExtendWith(MockitoExtension.class)
@DisplayName("EmailVerificationTokenService Tests")
public class EmailVerificationTokenServiceTest {
    @Mock
    private EmailVerificationTokenRepository emailVerificationTokenRepository;
    @Mock
    private EmailService emailService;
    @Mock
    private UserRepository userRepository;
    @Mock
    private SecurityContext securityContext;
    @Mock
    private Authentication authentication;
    @InjectMocks
    private EmailVerificationTokenService emailVerificationTokenService;

    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_FIRST_NAME = "John";
    private static final Long TEST_USER_ID = 1L;
    private static final String TEST_SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    private static final long TOKEN_EXPIRY_SECONDS = 86400L; // 24 hours
    private static final String EMAIL_BASE_URL = "http://localhost:8080";

    private User testUser;
    private String validToken;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(emailVerificationTokenService, "emailVerificationTokenExpiryS",
                TOKEN_EXPIRY_SECONDS);
        ReflectionTestUtils.setField(emailVerificationTokenService, "emailVerificationTokenSecretKey", TEST_SECRET_KEY);
        ReflectionTestUtils.setField(emailVerificationTokenService, "emailBaseUrl", EMAIL_BASE_URL);

        testUser = createTestUser(false);
        validToken = generateTestToken(TEST_EMAIL, TOKEN_EXPIRY_SECONDS);
        mockSecurityContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    // ===== createAndSendEmailVerificationToken Tests =====

    @Test
    @DisplayName("Should create and send email verification token successfully")
    void shouldCreateAndSendEmailVerificationTokenSuccessfully() {
        // Given
        when(emailVerificationTokenRepository.findByUserIdAndIsVerifiedFalse(TEST_USER_ID))
                .thenReturn(new ArrayList<>());
        when(emailVerificationTokenRepository.save(any(EmailVerificationToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        doNothing().when(emailService).sendVerificationEmail(anyString(), anyString(), anyString());

        // When
        emailVerificationTokenService.createAndSendEmailVerificationToken(testUser);

        // Then
        verify(emailVerificationTokenRepository, times(1)).save(any(EmailVerificationToken.class));
        verify(emailService, times(1)).sendVerificationEmail(eq(TEST_EMAIL), eq(TEST_FIRST_NAME), anyString());
    }

    @Test
    @DisplayName("Should invalidate existing unverified tokens before creating new one")
    void shouldInvalidateExistingUnverifiedTokens() {
        // Given
        EmailVerificationToken oldToken1 = createEmailVerificationToken(LocalDateTime.now().plusHours(1), false);
        EmailVerificationToken oldToken2 = createEmailVerificationToken(LocalDateTime.now().plusHours(2), false);

        when(emailVerificationTokenRepository.findByUserIdAndIsVerifiedFalse(TEST_USER_ID))
                .thenReturn(List.of(oldToken1, oldToken2));
        when(emailVerificationTokenRepository.save(any(EmailVerificationToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        doNothing().when(emailService).sendVerificationEmail(anyString(), anyString(), anyString());

        // When
        emailVerificationTokenService.createAndSendEmailVerificationToken(testUser);

        // Then
        verify(emailVerificationTokenRepository, times(3)).save(any(EmailVerificationToken.class)); // 2 old + 1 new
        assertThat(oldToken1.getIsVerified()).isTrue();
        assertThat(oldToken1.getVerifiedAt()).isNotNull();
        assertThat(oldToken2.getIsVerified()).isTrue();
        assertThat(oldToken2.getVerifiedAt()).isNotNull();
    }

    @Test
    @DisplayName("Should generate JWT token with correct claims")
    void shouldGenerateJwtTokenWithCorrectClaims() {
        // Given
        when(emailVerificationTokenRepository.findByUserIdAndIsVerifiedFalse(TEST_USER_ID))
                .thenReturn(new ArrayList<>());
        when(emailVerificationTokenRepository.save(any(EmailVerificationToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        doNothing().when(emailService).sendVerificationEmail(anyString(), anyString(), anyString());

        // When
        emailVerificationTokenService.createAndSendEmailVerificationToken(testUser);

        // Then
        ArgumentCaptor<EmailVerificationToken> tokenCaptor = ArgumentCaptor.forClass(EmailVerificationToken.class);
        verify(emailVerificationTokenRepository).save(tokenCaptor.capture());

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
        assertThat(claims.get("Purpose")).isEqualTo("email verifictaion");
        assertThat(claims.getIssuedAt()).isNotNull();
        assertThat(claims.getExpiration()).isNotNull();
    }

    @Test
    @DisplayName("Should set expiration time correctly when creating token")
    void shouldSetExpirationTimeCorrectly() {
        // Given
        when(emailVerificationTokenRepository.findByUserIdAndIsVerifiedFalse(TEST_USER_ID))
                .thenReturn(new ArrayList<>());
        when(emailVerificationTokenRepository.save(any(EmailVerificationToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        doNothing().when(emailService).sendVerificationEmail(anyString(), anyString(), anyString());

        LocalDateTime beforeCreation = LocalDateTime.now();

        // When
        emailVerificationTokenService.createAndSendEmailVerificationToken(testUser);

        // Then
        ArgumentCaptor<EmailVerificationToken> tokenCaptor = ArgumentCaptor.forClass(EmailVerificationToken.class);
        verify(emailVerificationTokenRepository).save(tokenCaptor.capture());

        LocalDateTime expiresAt = tokenCaptor.getValue().getExpiresAt();
        LocalDateTime expectedExpiry = beforeCreation.plusSeconds(TOKEN_EXPIRY_SECONDS);

        assertThat(expiresAt).isAfter(expectedExpiry.minusSeconds(5));
        assertThat(expiresAt).isBefore(expectedExpiry.plusSeconds(5));
    }

    @Test
    @DisplayName("Should send verification email with correct link")
    void shouldSendVerificationEmailWithCorrectLink() {
        // Given
        when(emailVerificationTokenRepository.findByUserIdAndIsVerifiedFalse(TEST_USER_ID))
                .thenReturn(new ArrayList<>());
        when(emailVerificationTokenRepository.save(any(EmailVerificationToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        doNothing().when(emailService).sendVerificationEmail(anyString(), anyString(), anyString());

        // When
        emailVerificationTokenService.createAndSendEmailVerificationToken(testUser);

        // Then
        ArgumentCaptor<String> linkCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailService).sendVerificationEmail(eq(TEST_EMAIL), eq(TEST_FIRST_NAME), linkCaptor.capture());

        String link = linkCaptor.getValue();
        assertThat(link).startsWith(EMAIL_BASE_URL + "/api/auth/verify-email?token=");
    }

    @Test
    @DisplayName("Should associate token with user")
    void shouldAssociateTokenWithUser() {
        // Given
        when(emailVerificationTokenRepository.findByUserIdAndIsVerifiedFalse(TEST_USER_ID))
                .thenReturn(new ArrayList<>());
        when(emailVerificationTokenRepository.save(any(EmailVerificationToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        doNothing().when(emailService).sendVerificationEmail(anyString(), anyString(), anyString());

        // When
        emailVerificationTokenService.createAndSendEmailVerificationToken(testUser);

        // Then
        ArgumentCaptor<EmailVerificationToken> tokenCaptor = ArgumentCaptor.forClass(EmailVerificationToken.class);
        verify(emailVerificationTokenRepository).save(tokenCaptor.capture());

        EmailVerificationToken savedToken = tokenCaptor.getValue();
        assertThat(savedToken.getUser()).isEqualTo(testUser);
        assertThat(savedToken.getIsVerified()).isFalse();
    }

    // ===== verifyEmail Tests =====

    @Test
    @DisplayName("Should verify email successfully")
    void shouldVerifyEmailSuccessfully() {
        // Given
        EmailVerificationToken token = createEmailVerificationToken(LocalDateTime.now().plusHours(1), false);
        token.setToken(validToken);

        when(emailVerificationTokenRepository.findByTokenAndIsVerifiedFalse(validToken))
                .thenReturn(Optional.of(token));
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(emailVerificationTokenRepository.save(any(EmailVerificationToken.class))).thenReturn(token);
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        emailVerificationTokenService.verifyEmail(validToken);

        // Then
        ArgumentCaptor<EmailVerificationToken> tokenCaptor = ArgumentCaptor.forClass(EmailVerificationToken.class);
        verify(emailVerificationTokenRepository).save(tokenCaptor.capture());
        assertThat(tokenCaptor.getValue().getIsVerified()).isTrue();

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        assertThat(userCaptor.getValue().getIsEmailVerified()).isTrue();
    }

    @Test
    @DisplayName("Should throw exception when token not found")
    void shouldThrowExceptionWhenTokenNotFound() {
        // Given
        when(emailVerificationTokenRepository.findByTokenAndIsVerifiedFalse(validToken))
                .thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> emailVerificationTokenService.verifyEmail(validToken))
                .isInstanceOf(EmailVerificationException.class)
                .hasMessageContaining("Invalid verification token");

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should throw exception when token is expired")
    void shouldThrowExceptionWhenTokenExpired() {
        // Given
        EmailVerificationToken expiredToken = createEmailVerificationToken(
                LocalDateTime.now().minusHours(1), // Expired
                false);
        expiredToken.setToken(validToken);

        when(emailVerificationTokenRepository.findByTokenAndIsVerifiedFalse(validToken))
                .thenReturn(Optional.of(expiredToken));

        // When & Then
        assertThatThrownBy(() -> emailVerificationTokenService.verifyEmail(validToken))
                .isInstanceOf(EmailVerificationException.class)
                .hasMessageContaining("Verification token has expired");

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should throw exception when email already verified")
    void shouldThrowExceptionWhenEmailAlreadyVerified() {
        // Given
        User verifiedUser = createTestUser(true);
        EmailVerificationToken token = createEmailVerificationToken(LocalDateTime.now().plusHours(1), false);
        token.setToken(validToken);

        when(emailVerificationTokenRepository.findByTokenAndIsVerifiedFalse(validToken))
                .thenReturn(Optional.of(token));
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(verifiedUser));

        // When & Then
        assertThatThrownBy(() -> emailVerificationTokenService.verifyEmail(validToken))
                .isInstanceOf(EmailVerificationException.class)
                .hasMessageContaining("Email is already verified");

        verify(emailVerificationTokenRepository, never()).save(any(EmailVerificationToken.class));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should throw exception when user from token not found")
    void shouldThrowExceptionWhenUserNotFound() {
        // Given
        EmailVerificationToken token = createEmailVerificationToken(LocalDateTime.now().plusHours(1), false);
        token.setToken(validToken);

        when(emailVerificationTokenRepository.findByTokenAndIsVerifiedFalse(validToken))
                .thenReturn(Optional.of(token));
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> emailVerificationTokenService.verifyEmail(validToken))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("User not found");
    }

    @Test
    @DisplayName("Should throw exception for invalid JWT signature")
    void shouldThrowExceptionForInvalidJwtSignature() {
        // Given
        String tamperedToken = validToken.substring(0, validToken.length() - 5) + "invalid";
        EmailVerificationToken token = createEmailVerificationToken(LocalDateTime.now().plusHours(1), false);
        token.setToken(tamperedToken);

        when(emailVerificationTokenRepository.findByTokenAndIsVerifiedFalse(tamperedToken))
                .thenReturn(Optional.of(token));

        // When & Then
        assertThatThrownBy(() -> emailVerificationTokenService.verifyEmail(tamperedToken))
                .isInstanceOf(Exception.class); // JwtException or its subclass

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should mark token as verified after successful verification")
    void shouldMarkTokenAsVerified() {
        // Given
        EmailVerificationToken token = createEmailVerificationToken(LocalDateTime.now().plusHours(1), false);
        token.setToken(validToken);

        when(emailVerificationTokenRepository.findByTokenAndIsVerifiedFalse(validToken))
                .thenReturn(Optional.of(token));
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(emailVerificationTokenRepository.save(any(EmailVerificationToken.class))).thenReturn(token);
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        emailVerificationTokenService.verifyEmail(validToken);

        // Then
        ArgumentCaptor<EmailVerificationToken> tokenCaptor = ArgumentCaptor.forClass(EmailVerificationToken.class);
        verify(emailVerificationTokenRepository).save(tokenCaptor.capture());

        EmailVerificationToken savedToken = tokenCaptor.getValue();
        assertThat(savedToken.getIsVerified()).isTrue();
    }

    // ===== resendVerificationEmail Tests =====

    @Test
    @DisplayName("Should resend verification email successfully")
    void shouldResendVerificationEmailSuccessfully() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(emailVerificationTokenRepository.findByUserIdAndIsVerifiedFalse(TEST_USER_ID))
                .thenReturn(new ArrayList<>());
        when(emailVerificationTokenRepository.save(any(EmailVerificationToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        doNothing().when(emailService).sendVerificationEmail(anyString(), anyString(), anyString());

        // When
        emailVerificationTokenService.resendVerificationEmail();

        // Then
        verify(userRepository, times(1)).findByEmail(TEST_EMAIL);
        verify(emailVerificationTokenRepository, times(1)).save(any(EmailVerificationToken.class));
        verify(emailService, times(1)).sendVerificationEmail(eq(TEST_EMAIL), eq(TEST_FIRST_NAME), anyString());
    }

    @Test
    @DisplayName("Should throw exception when email already verified")
    void shouldThrowExceptionWhenEmailAlreadyVerifiedForResend() {
        // Given
        User verifiedUser = createTestUser(true);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(verifiedUser));

        // When & Then
        assertThatThrownBy(() -> emailVerificationTokenService.resendVerificationEmail())
                .isInstanceOf(EmailVerificationException.class)
                .hasMessageContaining("This Email has already been verified");

        verify(emailVerificationTokenRepository, never()).save(any(EmailVerificationToken.class));
        verify(emailService, never()).sendVerificationEmail(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("Should throw exception when requesting too soon (cooldown period)")
    void shouldThrowExceptionWhenRequestingTooSoon() {
        // Given
        EmailVerificationToken recentToken = createEmailVerificationToken(
                LocalDateTime.now().plusHours(1),
                false);
        recentToken.setCreatedAt(LocalDateTime.now().minusMinutes(2)); // Created 2 minutes ago

        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(emailVerificationTokenRepository.findByUserIdAndIsVerifiedFalse(TEST_USER_ID))
                .thenReturn(List.of(recentToken));

        // When & Then
        assertThatThrownBy(() -> emailVerificationTokenService.resendVerificationEmail())
                .isInstanceOf(EmailVerificationException.class)
                .hasMessageContaining("Please wait before requesting another verification email");

        verify(emailVerificationTokenRepository, never()).save(any(EmailVerificationToken.class));
        verify(emailService, never()).sendVerificationEmail(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("Should allow resend after cooldown period expires")
    void shouldAllowResendAfterCooldownExpires() {
        // Given
        EmailVerificationToken oldToken = createEmailVerificationToken(
                LocalDateTime.now().plusHours(1),
                false);
        oldToken.setCreatedAt(LocalDateTime.now().minusMinutes(6)); // Created 6 minutes ago

        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(emailVerificationTokenRepository.findByUserIdAndIsVerifiedFalse(TEST_USER_ID))
                .thenReturn(List.of(oldToken));
        when(emailVerificationTokenRepository.save(any(EmailVerificationToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        doNothing().when(emailService).sendVerificationEmail(anyString(), anyString(), anyString());

        // When
        emailVerificationTokenService.resendVerificationEmail();

        // Then
        verify(emailVerificationTokenRepository, times(2)).save(any(EmailVerificationToken.class)); // 1 old invalidated
                                                                                                    // + 1 new
        verify(emailService, times(1)).sendVerificationEmail(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("Should throw exception when user not authenticated for resend")
    void shouldThrowExceptionWhenUserNotAuthenticatedForResend() {
        // Given
        when(authentication.isAuthenticated()).thenReturn(false);

        // When & Then
        assertThatThrownBy(() -> emailVerificationTokenService.resendVerificationEmail())
                .isInstanceOf(InsufficientAuthenticationException.class)
                .hasMessageContaining("User not logged in");

        verify(emailVerificationTokenRepository, never()).save(any(EmailVerificationToken.class));
    }

    @Test
    @DisplayName("Should throw exception when authenticated user not found")
    void shouldThrowExceptionWhenAuthenticatedUserNotFound() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> emailVerificationTokenService.resendVerificationEmail())
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("User not found");
    }

    // ===== deleteExpiredEmailVerificationTokens Tests =====

    @Test
    @DisplayName("Should delete expired tokens successfully")
    void shouldDeleteExpiredTokensSuccessfully() {
        // Given
        List<EmailVerificationToken> allTokens = createTokenList();
        when(emailVerificationTokenRepository.findAll()).thenReturn(allTokens);
        doNothing().when(emailVerificationTokenRepository).deleteAll(anyList());

        // When
        int deletedCount = emailVerificationTokenService.deleteExpiredEmailVerificationTokens();

        // Then
        assertThat(deletedCount).isEqualTo(2); // 2 expired tokens in createTokenList()

        ArgumentCaptor<List<EmailVerificationToken>> tokensCaptor = ArgumentCaptor.forClass(List.class);
        verify(emailVerificationTokenRepository).deleteAll(tokensCaptor.capture());

        List<EmailVerificationToken> deletedTokens = tokensCaptor.getValue();
        assertThat(deletedTokens).hasSize(2);
        assertThat(deletedTokens).allMatch(token -> token.getCreatedAt().isBefore(LocalDateTime.now()));
    }

    @Test
    @DisplayName("Should return zero when no expired tokens")
    void shouldReturnZeroWhenNoExpiredTokens() {
        // Given
        List<EmailVerificationToken> validTokens = List.of(
                createTokenWithCreatedAt(LocalDateTime.now().plusMinutes(10)),
                createTokenWithCreatedAt(LocalDateTime.now().plusMinutes(20)));
        when(emailVerificationTokenRepository.findAll()).thenReturn(validTokens);
        doNothing().when(emailVerificationTokenRepository).deleteAll(anyList());

        // When
        int deletedCount = emailVerificationTokenService.deleteExpiredEmailVerificationTokens();

        // Then
        assertThat(deletedCount).isEqualTo(0);

        ArgumentCaptor<List<EmailVerificationToken>> tokensCaptor = ArgumentCaptor.forClass(List.class);
        verify(emailVerificationTokenRepository).deleteAll(tokensCaptor.capture());
        assertThat(tokensCaptor.getValue()).isEmpty();
    }

    @Test
    @DisplayName("Should handle empty token list")
    void shouldHandleEmptyTokenList() {
        // Given
        when(emailVerificationTokenRepository.findAll()).thenReturn(new ArrayList<>());
        doNothing().when(emailVerificationTokenRepository).deleteAll(anyList());

        // When
        int deletedCount = emailVerificationTokenService.deleteExpiredEmailVerificationTokens();

        // Then
        assertThat(deletedCount).isEqualTo(0);
        verify(emailVerificationTokenRepository, times(1)).findAll();
        verify(emailVerificationTokenRepository, times(1)).deleteAll(anyList());
    }

    @Test
    @DisplayName("Should only delete tokens created before now")
    void shouldOnlyDeleteTokensCreatedBeforeNow() {
        // Given
        List<EmailVerificationToken> mixedTokens = List.of(
                createTokenWithCreatedAt(LocalDateTime.now().minusHours(1)), // Expired
                createTokenWithCreatedAt(LocalDateTime.now().plusMinutes(1)), // Valid
                createTokenWithCreatedAt(LocalDateTime.now().minusDays(1)), // Expired
                createTokenWithCreatedAt(LocalDateTime.now().plusHours(1)) // Valid
        );
        when(emailVerificationTokenRepository.findAll()).thenReturn(mixedTokens);
        doNothing().when(emailVerificationTokenRepository).deleteAll(anyList());

        // When
        int deletedCount = emailVerificationTokenService.deleteExpiredEmailVerificationTokens();

        // Then
        assertThat(deletedCount).isEqualTo(2);

        ArgumentCaptor<List<EmailVerificationToken>> tokensCaptor = ArgumentCaptor.forClass(List.class);
        verify(emailVerificationTokenRepository).deleteAll(tokensCaptor.capture());

        List<EmailVerificationToken> deletedTokens = tokensCaptor.getValue();
        assertThat(deletedTokens).allMatch(token -> token.getCreatedAt().isBefore(LocalDateTime.now()));
    }

    // ===== Helper Methods =====

    private User createTestUser(boolean isEmailVerified) {
        User user = new User();
        user.setId(TEST_USER_ID);
        user.setEmail(TEST_EMAIL);
        user.setUsername("testuser");
        user.setFirstName(TEST_FIRST_NAME);
        user.setLastName("Doe");
        user.setIsActive(true);
        user.setIsEmailVerified(isEmailVerified);
        user.setIsLocked(false);
        return user;
    }

    private EmailVerificationToken createEmailVerificationToken(LocalDateTime expiresAt, boolean isVerified) {
        EmailVerificationToken token = new EmailVerificationToken();
        token.setId(1L);
        token.setUser(testUser);
        token.setToken("some-token");
        token.setExpiresAt(expiresAt);
        token.setIsVerified(isVerified);
        token.setCreatedAt(LocalDateTime.now().minusMinutes(10)); // Default created 10 minutes ago
        if (isVerified) {
            token.setVerifiedAt(LocalDateTime.now().minusMinutes(5));
        }
        return token;
    }

    private EmailVerificationToken createTokenWithCreatedAt(LocalDateTime createdAt) {
        EmailVerificationToken token = new EmailVerificationToken();
        token.setToken(UUID.randomUUID().toString());
        token.setUser(testUser);
        token.setExpiresAt(LocalDateTime.now().plusHours(1));
        token.setIsVerified(false);
        token.setCreatedAt(createdAt);
        return token;
    }

    private List<EmailVerificationToken> createTokenList() {
        List<EmailVerificationToken> tokens = new ArrayList<>();

        // Valid tokens (created in the future - shouldn't happen but for testing)
        tokens.add(createTokenWithCreatedAt(LocalDateTime.now().plusMinutes(10)));
        tokens.add(createTokenWithCreatedAt(LocalDateTime.now().plusMinutes(20)));

        // Expired tokens (created in the past)
        tokens.add(createTokenWithCreatedAt(LocalDateTime.now().minusHours(1)));
        tokens.add(createTokenWithCreatedAt(LocalDateTime.now().minusDays(1)));

        return tokens;
    }

    private String generateTestToken(String email, long expirySeconds) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(email)
                .claim("Purpose", "email verifictaion")
                .issuedAt(new Date(now))
                .expiration(new Date(now + (expirySeconds * 1000)))
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
