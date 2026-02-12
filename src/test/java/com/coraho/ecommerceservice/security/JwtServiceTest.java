package com.coraho.ecommerceservice.security;

import java.util.*;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.DecodingException;
import io.jsonwebtoken.security.Keys;

import static org.mockito.Mockito.when;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtService Tests")
public class JwtServiceTest {

    @Mock
    private Authentication authentication;

    @InjectMocks
    private JwtService jwtService;

    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    private static final long TEST_EXPIRATION_MS = 3600000; // 1 hour
    private static final long SHORT_EXPIRATION_MS = 1000; // 1 second for expiry tests

    private UserDetails userDetails;

    @BeforeEach
    void setUp() {
        // Set @Value fields
        ReflectionTestUtils.setField(jwtService, "secretKey", TEST_SECRET_KEY);
        ReflectionTestUtils.setField(jwtService, "jwtExpirationMs", TEST_EXPIRATION_MS);

        // Create UserDetails with authorities
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("product:read"));

        userDetails = new User(TEST_EMAIL, "password", authorities);
    }

    @Test
    @DisplayName("Should generate valid JWT token with correct claims")
    void shouldGenerateValidTokenWithCorrectClaims() {
        // Stub the return value
        when(authentication.getPrincipal()).thenReturn(userDetails);

        String token = jwtService.generateToken(authentication);

        assertThat(token).isNotNull();
        assertThat(token).isNotEmpty();

        // Verify token structure
        assertThat(token.split("\\.")).hasSize(3);

        // Verify token is valid
        assertThat(jwtService.isTokenValid(token)).isTrue();
    }

    @Test
    @DisplayName("Should set correct subject (emial) in generated token")
    void shouldSetCorrectSubjectInToken() {
        when(authentication.getPrincipal()).thenReturn(userDetails);

        String token = jwtService.generateToken(authentication);
        String extractedEmail = jwtService.getUsernameFromToken(token);

        assertThat(extractedEmail).isEqualTo(TEST_EMAIL);
    }

    @Test
    @DisplayName("Should set correct authorities in generated token")
    void shouldIncludeAuthoritiesInTokenClaims() {
        when(authentication.getPrincipal()).thenReturn(userDetails);

        String token = jwtService.generateToken(authentication);

        // Parse token to verify authorities claim
        Claims claims = Jwts.parser()
                .verifyWith((SecretKey) Keys.hmacShaKeyFor(Base64.getDecoder().decode(TEST_SECRET_KEY)))
                .build()
                .parseSignedClaims(token)
                .getPayload();

        @SuppressWarnings("unchecked")
        List<String> authorities = (List<String>) claims.get("authorities");

        assertThat(authorities).containsExactlyInAnyOrder("ROLE_USER", "product:read");
    }

    @Test
    @DisplayName("Should set issued date and expiration date in token")
    void shouldSetIssuedAndExpirationDates() {
        when(authentication.getPrincipal()).thenReturn(userDetails);

        long beforeGeneration = System.currentTimeMillis();
        String token = jwtService.generateToken(authentication);
        long afterGeneration = System.currentTimeMillis();

        // Parse token to verify authorities claim
        Claims claims = Jwts.parser()
                .verifyWith((SecretKey) Keys.hmacShaKeyFor(Base64.getDecoder().decode(TEST_SECRET_KEY)))
                .build()
                .parseSignedClaims(token)
                .getPayload();

        assertThat(claims.getIssuedAt()).isNotNull();
        assertThat(claims.getExpiration()).isNotNull();

        assertThat(claims.getIssuedAt().getTime()).isBetween(beforeGeneration - 1000, afterGeneration + 1000);
        long expectedExpiry = claims.getIssuedAt().getTime() + TEST_EXPIRATION_MS;
        assertThat(claims.getExpiration().getTime()).isBetween(expectedExpiry - 1000, expectedExpiry + 1000);
    }

    @Test
    @DisplayName("Should extract username from valid token")
    void shouldExtractUsernameFromValidToken() {
        // Given
        when(authentication.getPrincipal()).thenReturn(userDetails);
        String token = jwtService.generateToken(authentication);

        // When
        String username = jwtService.getUsernameFromToken(token);

        // Then
        assertThat(username).isEqualTo(TEST_EMAIL);
    }

    @Test
    @DisplayName("Should validate valid token successfully")
    void shouldValidateValidTokenSuccessfully() {
        // Given
        when(authentication.getPrincipal()).thenReturn(userDetails);
        String token = jwtService.generateToken(authentication);

        // When
        boolean isValid = jwtService.isTokenValid(token);

        // Then
        assertThat(isValid).isTrue();
    }

    @Test
    @DisplayName("Should return false for null token")
    void shouldReturnFalseForNullToken() {
        // When
        boolean isValid = jwtService.isTokenValid(null);

        // Then
        assertThat(isValid).isFalse();
    }

    @Test
    @DisplayName("Should return false for empty token")
    void shouldReturnFalseForEmptyToken() {
        // When
        boolean isValid = jwtService.isTokenValid("");

        // Then
        assertThat(isValid).isFalse();
    }

    @Test
    @DisplayName("Should return false for whitespace-only token")
    void shouldReturnFalseForWhitespaceToken() {
        // When
        boolean isValid = jwtService.isTokenValid("   ");

        // Then
        assertThat(isValid).isFalse();
    }

    @Test
    @DisplayName("Should throw MalformedJwtException for malformed token")
    void shouldThrowMalformedJwtExceptionForMalformedToken() {
        // Given
        String malformedToken = "this.is.not.a.valid.jwt";

        // When & Then
        assertThatThrownBy(() -> jwtService.isTokenValid(malformedToken))
                .isInstanceOf(MalformedJwtException.class)
                .hasMessageContaining("Invalid JWT token");
    }

    @Test
    @DisplayName("Should throw MalformedJwtException when extracting username from malformed token")
    void shouldThrowMalformedJwtExceptionWhenExtractingFromMalformedToken() {
        // Given
        String malformedToken = "not.a.valid.token";

        // When & Then
        assertThatThrownBy(() -> jwtService.getUsernameFromToken(malformedToken))
                .isInstanceOf(MalformedJwtException.class)
                .hasMessageContaining("Invalid JWT token");
    }

    @Test
    @DisplayName("Should throw ExpiredJwtException for expired token")
    void shouldThrowExpiredJwtExceptionForExpiredToken() throws InterruptedException {
        // Given
        ReflectionTestUtils.setField(jwtService, "jwtExpirationMs", SHORT_EXPIRATION_MS);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        String token = jwtService.generateToken(authentication);

        // Wait for token to expire
        Thread.sleep(1500);

        // When & Then
        assertThatThrownBy(() -> jwtService.isTokenValid(token))
                .isInstanceOf(ExpiredJwtException.class)
                .hasMessageContaining("JWT token is expired");
    }

    @Test
    @DisplayName("Should throw ExpiredJwtException when extracting from expired token")
    void shouldThrowExpiredJwtExceptionWhenExtractingFromExpiredToken() throws InterruptedException {
        // Given
        ReflectionTestUtils.setField(jwtService, "jwtExpirationMs", SHORT_EXPIRATION_MS);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        String token = jwtService.generateToken(authentication);

        Thread.sleep(1500);

        // When & Then
        assertThatThrownBy(() -> jwtService.getUsernameFromToken(token))
                .isInstanceOf(ExpiredJwtException.class)
                .hasMessageContaining("JWT token is expired");
    }

    @Test
    @DisplayName("Should throw SecurityException for token with invalid signature")
    void shouldThrowSecurityExceptionForInvalidSignature() {
        // Given
        when(authentication.getPrincipal()).thenReturn(userDetails);
        String token = jwtService.generateToken(authentication);

        // Tamper with the signature
        String[] parts = token.split("\\.");
        String tamperedToken = parts[0] + "." + parts[1] + ".tampered_signature";

        // When & Then
        assertThatThrownBy(() -> jwtService.isTokenValid(tamperedToken))
                .isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("Should throw SecurityException when extracting from token with invalid signature")
    void shouldThrowSecurityExceptionWhenExtractingFromInvalidSignature() {
        // Given
        when(authentication.getPrincipal()).thenReturn(userDetails);
        String token = jwtService.generateToken(authentication);

        String[] parts = token.split("\\.");
        String tamperedToken = parts[0] + "." + parts[1] + ".invalid";

        // When & Then
        assertThatThrownBy(() -> jwtService.getUsernameFromToken(tamperedToken))
                .isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("Should handle user with multiple authorities")
    void shouldHandleUserWithMultipleAuthorities() {
        // Given
        List<GrantedAuthority> multipleAuthorities = List.of(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_ADMIN"),
                new SimpleGrantedAuthority("READ_PRIVILEGE"),
                new SimpleGrantedAuthority("WRITE_PRIVILEGE"),
                new SimpleGrantedAuthority("DELETE_PRIVILEGE"));

        UserDetails userWithMultipleRoles = new User(TEST_EMAIL, "password", multipleAuthorities);
        when(authentication.getPrincipal()).thenReturn(userWithMultipleRoles);

        // When
        String token = jwtService.generateToken(authentication);

        // Then
        Claims claims = Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(TEST_SECRET_KEY)))
                .build()
                .parseSignedClaims(token)
                .getPayload();

        @SuppressWarnings("unchecked")
        List<String> authorities = (List<String>) claims.get("authorities");

        assertThat(authorities).hasSize(5);
        assertThat(authorities).containsExactlyInAnyOrder(
                "ROLE_USER", "ROLE_ADMIN",
                "READ_PRIVILEGE", "WRITE_PRIVILEGE", "DELETE_PRIVILEGE");
    }

    @Test
    @DisplayName("Should handle user with no authorities")
    void shouldHandleUserWithNoAuthorities() {
        // Given
        UserDetails userWithNoAuthorities = new User(TEST_EMAIL, "password", List.of());
        when(authentication.getPrincipal()).thenReturn(userWithNoAuthorities);

        // When
        String token = jwtService.generateToken(authentication);

        // Then
        assertThat(token).isNotNull();
        assertThat(jwtService.isTokenValid(token)).isTrue();

        Claims claims = Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(TEST_SECRET_KEY)))
                .build()
                .parseSignedClaims(token)
                .getPayload();

        @SuppressWarnings("unchecked")
        List<String> authorities = (List<String>) claims.get("authorities");

        assertThat(authorities).isEmpty();
    }

    @Test
    @DisplayName("Should generate different tokens for same user at different times")
    void shouldGenerateDifferentTokensForSameUser() throws InterruptedException {
        // Given
        when(authentication.getPrincipal()).thenReturn(userDetails);

        // When
        String token1 = jwtService.generateToken(authentication);
        Thread.sleep(1000); // Small delay to ensure different issued time
        String token2 = jwtService.generateToken(authentication);

        // Then
        assertThat(token1).isNotEqualTo(token2);
        assertThat(jwtService.isTokenValid(token1)).isTrue();
        assertThat(jwtService.isTokenValid(token2)).isTrue();
    }

    @Test
    @DisplayName("Should throw DecodingException for invalid base64 secret key")
    void shouldHandleInvalidSecretKey() {
        // Given
        ReflectionTestUtils.setField(jwtService, "secretKey", "invalid-base64!");
        when(authentication.getPrincipal()).thenReturn(userDetails);

        // When & Then
        assertThatThrownBy(() -> jwtService.generateToken(authentication))
                .isInstanceOf(DecodingException.class);
    }

}
