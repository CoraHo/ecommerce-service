package com.coraho.ecommerceservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
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

import com.coraho.ecommerceservice.DTO.AuthResponse;
import com.coraho.ecommerceservice.entity.RefreshToken;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.exception.RefreshTokenException;
import com.coraho.ecommerceservice.exception.ResourceNotFoundException;
import com.coraho.ecommerceservice.repository.RefreshTokenRepository;
import com.coraho.ecommerceservice.repository.UserRepository;
import com.coraho.ecommerceservice.security.JwtService;

@ExtendWith(MockitoExtension.class)
@DisplayName("RefreshTokenService Tests")
public class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private JwtService jwtService;
    @Mock
    private SecurityContext securityContext;
    @Mock
    private Authentication authentication;
    @InjectMocks
    private RefreshTokenService refreshTokenService;

    private static final Long TEST_USER_ID = 1L;
    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_USERNAME = "testuser";
    private static final String TEST_REFRESH_TOKEN = "refresh-token-uuid";
    private static final String TEST_ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
    private static final String TEST_IP_ADDRESS = "192.168.1.1";
    private static final String TEST_USER_AGENT = "Mozilla/5.0";
    private static final long TEST_EXPIRATION_SECONDS = 604800L; // 7 days

    private User testUser;
    private RefreshToken testRefreshToken;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(refreshTokenService, "refreshTokenExpirationS", TEST_EXPIRATION_SECONDS);
        testUser = createTestUser();
        testRefreshToken = createTestRefreshToken(false);
        mockSecurityContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    // ===== createRefreshToken Tests =====

    @Test
    @DisplayName("Should create refresh token successfully")
    void shouldCreateRefreshTokenSuccessfully() {
        // Given
        when(userRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(testUser));
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(testRefreshToken);

        // When
        RefreshToken result = refreshTokenService.createRefreshToken(TEST_USER_ID, TEST_IP_ADDRESS, TEST_USER_AGENT);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getToken()).isNotNull();
        assertThat(result.getUser()).isEqualTo(testUser);
        assertThat(result.getIpAddress()).isEqualTo(TEST_IP_ADDRESS);
        assertThat(result.getUserAgent()).isEqualTo(TEST_USER_AGENT);

        verify(userRepository, times(1)).findById(TEST_USER_ID);
        verify(refreshTokenRepository, times(1)).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("Should generate UUID token when creating refresh token")
    void shouldGenerateUuidToken() {
        // Given
        when(userRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(testUser));
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // When
        refreshTokenService.createRefreshToken(TEST_USER_ID, TEST_IP_ADDRESS, TEST_USER_AGENT);

        // Then
        ArgumentCaptor<RefreshToken> tokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(tokenCaptor.capture());

        String token = tokenCaptor.getValue().getToken();
        assertThat(token).isNotNull();
        // Verify it's a valid UUID format
        assertThatCode(() -> UUID.fromString(token)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("Should set expiration time correctly when creating refresh token")
    void shouldSetExpirationTimeCorrectly() {
        // Given
        when(userRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(testUser));
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        LocalDateTime beforeCreation = LocalDateTime.now();

        // When
        refreshTokenService.createRefreshToken(TEST_USER_ID, TEST_IP_ADDRESS, TEST_USER_AGENT);

        // Then
        ArgumentCaptor<RefreshToken> tokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(tokenCaptor.capture());

        LocalDateTime expiresAt = tokenCaptor.getValue().getExpiresAt();
        LocalDateTime expectedExpiry = beforeCreation.plusSeconds(TEST_EXPIRATION_SECONDS);

        assertThat(expiresAt).isAfter(expectedExpiry.minusSeconds(5));
        assertThat(expiresAt).isBefore(expectedExpiry.plusSeconds(5));
    }

    @Test
    @DisplayName("Should throw UsernameNotFoundException when user not found")
    void shouldThrowExceptionWhenUserNotFoundForCreate() {
        // Given
        when(userRepository.findById(TEST_USER_ID)).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> refreshTokenService.createRefreshToken(TEST_USER_ID, TEST_IP_ADDRESS, TEST_USER_AGENT))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("User Not Found");

        verify(userRepository, times(1)).findById(TEST_USER_ID);
        verify(refreshTokenRepository, never()).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("Should save refresh token with IP address and user agent")
    void shouldSaveRefreshTokenWithMetadata() {
        // Given
        when(userRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(testUser));
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // When
        refreshTokenService.createRefreshToken(TEST_USER_ID, TEST_IP_ADDRESS, TEST_USER_AGENT);

        // Then
        ArgumentCaptor<RefreshToken> tokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(tokenCaptor.capture());

        RefreshToken savedToken = tokenCaptor.getValue();
        assertThat(savedToken.getIpAddress()).isEqualTo(TEST_IP_ADDRESS);
        assertThat(savedToken.getUserAgent()).isEqualTo(TEST_USER_AGENT);
        assertThat(savedToken.getUser()).isEqualTo(testUser);
    }

    // ===== refreshAccessToken Tests =====

    @Test
    @DisplayName("Should refresh access token successfully")
    void shouldRefreshAccessTokenSuccessfully() {
        // Given
        when(refreshTokenRepository.findByToken(TEST_REFRESH_TOKEN)).thenReturn(Optional.of(testRefreshToken));
        when(jwtService.generateToken(authentication)).thenReturn(TEST_ACCESS_TOKEN);

        // When
        AuthResponse response = refreshTokenService.refreshAccessToken(TEST_REFRESH_TOKEN);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isEqualTo(TEST_ACCESS_TOKEN);
        assertThat(response.getRefreshToken()).isEqualTo(TEST_REFRESH_TOKEN);
        assertThat(response.getUsername()).isEqualTo(TEST_USERNAME);
        assertThat(response.getEmail()).isEqualTo(TEST_EMAIL);

        verify(refreshTokenRepository, times(1)).findByToken(TEST_REFRESH_TOKEN);
        verify(jwtService, times(1)).generateToken(authentication);
    }

    @Test
    @DisplayName("Should throw ResourceNotFoundException when refresh token not found")
    void shouldThrowExceptionWhenRefreshTokenNotFound() {
        // Given
        when(refreshTokenRepository.findByToken(TEST_REFRESH_TOKEN)).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> refreshTokenService.refreshAccessToken(TEST_REFRESH_TOKEN))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Refresh Token not found");

        verify(refreshTokenRepository, times(1)).findByToken(TEST_REFRESH_TOKEN);
        verify(jwtService, never()).generateToken(any(Authentication.class));
    }

    @Test
    @DisplayName("Should throw RefreshTokenException when token is expired")
    void shouldThrowExceptionWhenTokenExpired() {
        // Given
        RefreshToken expiredToken = createExpiredRefreshToken();
        when(refreshTokenRepository.findByToken(TEST_REFRESH_TOKEN)).thenReturn(Optional.of(expiredToken));
        doNothing().when(refreshTokenRepository).delete(expiredToken);

        // When & Then
        assertThatThrownBy(() -> refreshTokenService.refreshAccessToken(TEST_REFRESH_TOKEN))
                .isInstanceOf(RefreshTokenException.class)
                .hasMessageContaining("Refresh token expired");

        verify(refreshTokenRepository, times(1)).findByToken(TEST_REFRESH_TOKEN);
        verify(refreshTokenRepository, times(1)).delete(expiredToken);
        verify(jwtService, never()).generateToken(any(Authentication.class));
    }

    @Test
    @DisplayName("Should throw RefreshTokenException when token is revoked")
    void shouldThrowExceptionWhenTokenRevoked() {
        // Given
        RefreshToken revokedToken = createTestRefreshToken(true);
        when(refreshTokenRepository.findByToken(TEST_REFRESH_TOKEN)).thenReturn(Optional.of(revokedToken));

        // When & Then
        assertThatThrownBy(() -> refreshTokenService.refreshAccessToken(TEST_REFRESH_TOKEN))
                .isInstanceOf(RefreshTokenException.class)
                .hasMessageContaining("Refresh token has been revoked");

        verify(refreshTokenRepository, times(1)).findByToken(TEST_REFRESH_TOKEN);
        verify(jwtService, never()).generateToken(any(Authentication.class));
    }

    @Test
    @DisplayName("Should delete expired token from database during verification")
    void shouldDeleteExpiredTokenDuringVerification() {
        // Given
        RefreshToken expiredToken = createExpiredRefreshToken();
        when(refreshTokenRepository.findByToken(TEST_REFRESH_TOKEN)).thenReturn(Optional.of(expiredToken));
        doNothing().when(refreshTokenRepository).delete(expiredToken);

        // When & Then
        assertThatThrownBy(() -> refreshTokenService.refreshAccessToken(TEST_REFRESH_TOKEN))
                .isInstanceOf(RefreshTokenException.class);

        verify(refreshTokenRepository, times(1)).delete(expiredToken);
    }

    @Test
    @DisplayName("Should throw InsufficientAuthenticationException when user not authenticated")
    void shouldThrowExceptionWhenUserNotAuthenticatedForRefresh() {
        // Given
        when(refreshTokenRepository.findByToken(TEST_REFRESH_TOKEN)).thenReturn(Optional.of(testRefreshToken));
        when(authentication.isAuthenticated()).thenReturn(false);

        // When & Then
        assertThatThrownBy(() -> refreshTokenService.refreshAccessToken(TEST_REFRESH_TOKEN))
                .isInstanceOf(InsufficientAuthenticationException.class)
                .hasMessageContaining("User not logged in");

        verify(jwtService, never()).generateToken(any(Authentication.class));
    }

    // ===== revokeToken Tests =====

    @Test
    @DisplayName("Should revoke token successfully")
    void shouldRevokeTokenSuccessfully() {
        // Given
        when(refreshTokenRepository.findByToken(TEST_REFRESH_TOKEN)).thenReturn(Optional.of(testRefreshToken));
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(testRefreshToken);

        // When
        refreshTokenService.revokeToken(TEST_REFRESH_TOKEN);

        // Then
        ArgumentCaptor<RefreshToken> tokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(tokenCaptor.capture());

        RefreshToken revokedToken = tokenCaptor.getValue();
        assertThat(revokedToken.getIsRevoked()).isTrue();
        assertThat(revokedToken.getRevokedAt()).isNotNull();
        assertThat(revokedToken.getRevokedAt()).isBefore(LocalDateTime.now().plusSeconds(1));
    }

    @Test
    @DisplayName("Should throw RefreshTokenException when token not found for revocation")
    void shouldThrowExceptionWhenTokenNotFoundForRevocation() {
        // Given
        when(refreshTokenRepository.findByToken(TEST_REFRESH_TOKEN)).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> refreshTokenService.revokeToken(TEST_REFRESH_TOKEN))
                .isInstanceOf(RefreshTokenException.class)
                .hasMessageContaining("Refresh token not found");

        verify(refreshTokenRepository, times(1)).findByToken(TEST_REFRESH_TOKEN);
        verify(refreshTokenRepository, never()).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("Should set revokedAt timestamp when revoking token")
    void shouldSetRevokedAtTimestamp() {
        // Given
        when(refreshTokenRepository.findByToken(TEST_REFRESH_TOKEN)).thenReturn(Optional.of(testRefreshToken));
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(testRefreshToken);

        LocalDateTime beforeRevoke = LocalDateTime.now();

        // When
        refreshTokenService.revokeToken(TEST_REFRESH_TOKEN);

        // Then
        ArgumentCaptor<RefreshToken> tokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(tokenCaptor.capture());

        LocalDateTime revokedAt = tokenCaptor.getValue().getRevokedAt();
        assertThat(revokedAt).isAfterOrEqualTo(beforeRevoke.minusSeconds(1));
        assertThat(revokedAt).isBeforeOrEqualTo(LocalDateTime.now().plusSeconds(1));
    }

    // ===== revokeAllUserTokens Tests =====

    @Test
    @DisplayName("Should revoke all user tokens successfully")
    void shouldRevokeAllUserTokensSuccessfully() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        doNothing().when(refreshTokenRepository).revokeAllUserTokens(eq(TEST_USER_ID), any(LocalDateTime.class));

        // When
        refreshTokenService.revokeAllUserTokens();

        // Then
        verify(userRepository, times(1)).findByEmail(TEST_EMAIL);
        verify(refreshTokenRepository, times(1)).revokeAllUserTokens(eq(TEST_USER_ID), any(LocalDateTime.class));
    }

    @Test
    @DisplayName("Should pass current timestamp when revoking all user tokens")
    void shouldPassCurrentTimestampWhenRevokingAll() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        doNothing().when(refreshTokenRepository).revokeAllUserTokens(eq(TEST_USER_ID), any(LocalDateTime.class));

        LocalDateTime beforeRevoke = LocalDateTime.now();

        // When
        refreshTokenService.revokeAllUserTokens();

        // Then
        ArgumentCaptor<LocalDateTime> timestampCaptor = ArgumentCaptor.forClass(LocalDateTime.class);
        verify(refreshTokenRepository).revokeAllUserTokens(eq(TEST_USER_ID), timestampCaptor.capture());

        LocalDateTime capturedTimestamp = timestampCaptor.getValue();
        assertThat(capturedTimestamp).isAfterOrEqualTo(beforeRevoke.minusSeconds(1));
        assertThat(capturedTimestamp).isBeforeOrEqualTo(LocalDateTime.now().plusSeconds(1));
    }

    @Test
    @DisplayName("Should throw InsufficientAuthenticationException when user not authenticated for revoke all")
    void shouldThrowExceptionWhenUserNotAuthenticatedForRevokeAll() {
        // Given
        when(authentication.isAuthenticated()).thenReturn(false);

        // When & Then
        assertThatThrownBy(() -> refreshTokenService.revokeAllUserTokens())
                .isInstanceOf(InsufficientAuthenticationException.class)
                .hasMessageContaining("User not logged in");

        verify(refreshTokenRepository, never()).revokeAllUserTokens(anyLong(), any(LocalDateTime.class));
    }

    @Test
    @DisplayName("Should throw UsernameNotFoundException when user not found for revoke all")
    void shouldThrowExceptionWhenUserNotFoundForRevokeAll() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> refreshTokenService.revokeAllUserTokens())
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("User not found");

        verify(refreshTokenRepository, never()).revokeAllUserTokens(anyLong(), any(LocalDateTime.class));
    }

    // ===== deleteExpiredRefreshTokens Tests =====

    @Test
    @DisplayName("Should delete expired refresh tokens successfully")
    void shouldDeleteExpiredRefreshTokensSuccessfully() {
        // Given
        List<RefreshToken> allTokens = createTokenList();
        when(refreshTokenRepository.findAll()).thenReturn(allTokens);
        doNothing().when(refreshTokenRepository).deleteAll(anyList());

        // When
        int deletedCount = refreshTokenService.deleteExpiredRefreshTokens();

        // Then
        assertThat(deletedCount).isEqualTo(2); // 2 expired tokens in createTokenList()

        ArgumentCaptor<List<RefreshToken>> tokensCaptor = ArgumentCaptor.forClass(List.class);
        verify(refreshTokenRepository).deleteAll(tokensCaptor.capture());

        List<RefreshToken> deletedTokens = tokensCaptor.getValue();
        assertThat(deletedTokens).hasSize(2);
        assertThat(deletedTokens).allMatch(token -> token.getExpiresAt().isBefore(LocalDateTime.now()));
    }

    @Test
    @DisplayName("Should return zero when no expired tokens")
    void shouldReturnZeroWhenNoExpiredTokens() {
        // Given
        List<RefreshToken> validTokens = List.of(
                createTokenWithExpiry(LocalDateTime.now().plusDays(1)),
                createTokenWithExpiry(LocalDateTime.now().plusDays(2)));
        when(refreshTokenRepository.findAll()).thenReturn(validTokens);
        doNothing().when(refreshTokenRepository).deleteAll(anyList());

        // When
        int deletedCount = refreshTokenService.deleteExpiredRefreshTokens();

        // Then
        assertThat(deletedCount).isEqualTo(0);

        ArgumentCaptor<List<RefreshToken>> tokensCaptor = ArgumentCaptor.forClass(List.class);
        verify(refreshTokenRepository).deleteAll(tokensCaptor.capture());
        assertThat(tokensCaptor.getValue()).isEmpty();
    }

    @Test
    @DisplayName("Should handle empty token list")
    void shouldHandleEmptyTokenList() {
        // Given
        when(refreshTokenRepository.findAll()).thenReturn(new ArrayList<>());
        doNothing().when(refreshTokenRepository).deleteAll(anyList());

        // When
        int deletedCount = refreshTokenService.deleteExpiredRefreshTokens();

        // Then
        assertThat(deletedCount).isEqualTo(0);
        verify(refreshTokenRepository, times(1)).findAll();
        verify(refreshTokenRepository, times(1)).deleteAll(anyList());
    }

    // ===== isTokenValid Tests =====

    @Test
    @DisplayName("Should return true for valid non-revoked token")
    void shouldReturnTrueForValidToken() {
        // Given
        when(refreshTokenRepository.existsByTokenAndIsRevokedFalse(TEST_REFRESH_TOKEN)).thenReturn(true);

        // When
        boolean isValid = refreshTokenService.isTokenValid(TEST_REFRESH_TOKEN);

        // Then
        assertThat(isValid).isTrue();
        verify(refreshTokenRepository, times(1)).existsByTokenAndIsRevokedFalse(TEST_REFRESH_TOKEN);
    }

    @Test
    @DisplayName("Should return false for invalid token")
    void shouldReturnFalseForInvalidToken() {
        // Given
        String invalidToken = "invalid-token";
        when(refreshTokenRepository.existsByTokenAndIsRevokedFalse(invalidToken)).thenReturn(false);

        // When
        boolean isValid = refreshTokenService.isTokenValid(invalidToken);

        // Then
        assertThat(isValid).isFalse();
        verify(refreshTokenRepository, times(1)).existsByTokenAndIsRevokedFalse(invalidToken);
    }

    @Test
    @DisplayName("Should return false for revoked token")
    void shouldReturnFalseForRevokedToken() {
        // Given
        when(refreshTokenRepository.existsByTokenAndIsRevokedFalse(TEST_REFRESH_TOKEN)).thenReturn(false);

        // When
        boolean isValid = refreshTokenService.isTokenValid(TEST_REFRESH_TOKEN);

        // Then
        assertThat(isValid).isFalse();
    }

    // ===== Helper Methods =====

    private User createTestUser() {
        User user = new User();
        user.setId(TEST_USER_ID);
        user.setEmail(TEST_EMAIL);
        user.setUsername(TEST_USERNAME);
        user.setFirstName("John");
        user.setLastName("Doe");
        user.setIsActive(true);
        user.setIsEmailVerified(true);
        user.setIsLocked(false);
        return user;
    }

    private RefreshToken createTestRefreshToken(boolean isRevoked) {
        RefreshToken token = new RefreshToken();
        token.setId(1L);
        token.setToken(TEST_REFRESH_TOKEN);
        token.setUser(testUser);
        token.setExpiresAt(LocalDateTime.now().plusDays(7));
        token.setIpAddress(TEST_IP_ADDRESS);
        token.setUserAgent(TEST_USER_AGENT);
        token.setIsRevoked(isRevoked);
        if (isRevoked) {
            token.setRevokedAt(LocalDateTime.now().minusHours(1));
        }
        return token;
    }

    private RefreshToken createExpiredRefreshToken() {
        RefreshToken token = new RefreshToken();
        token.setId(1L);
        token.setToken(TEST_REFRESH_TOKEN);
        token.setUser(testUser);
        token.setExpiresAt(LocalDateTime.now().minusDays(1)); // Expired yesterday
        token.setIpAddress(TEST_IP_ADDRESS);
        token.setUserAgent(TEST_USER_AGENT);
        token.setIsRevoked(false);
        return token;
    }

    private RefreshToken createTokenWithExpiry(LocalDateTime expiresAt) {
        RefreshToken token = new RefreshToken();
        token.setToken(UUID.randomUUID().toString());
        token.setUser(testUser);
        token.setExpiresAt(expiresAt);
        token.setIsRevoked(false);
        return token;
    }

    private List<RefreshToken> createTokenList() {
        List<RefreshToken> tokens = new ArrayList<>();

        // Valid tokens
        tokens.add(createTokenWithExpiry(LocalDateTime.now().plusDays(1)));
        tokens.add(createTokenWithExpiry(LocalDateTime.now().plusDays(2)));

        // Expired tokens
        tokens.add(createTokenWithExpiry(LocalDateTime.now().minusDays(1)));
        tokens.add(createTokenWithExpiry(LocalDateTime.now().minusHours(1)));

        return tokens;
    }

    private void mockSecurityContext() {
        lenient().when(authentication.isAuthenticated()).thenReturn(true);
        lenient().when(authentication.getName()).thenReturn(TEST_EMAIL);
        lenient().when(securityContext.getAuthentication()).thenReturn(authentication);
        SecurityContextHolder.setContext(securityContext);
    }
}
