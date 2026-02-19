package com.coraho.ecommerceservice.repository;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.*;

import java.time.LocalDateTime;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import com.coraho.ecommerceservice.entity.RefreshToken;
import com.coraho.ecommerceservice.entity.User;

@DataJpaTest(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
@DisplayName("RefreshTokenRepository Tests")
public class RefreshTokenRepositoryTest {
    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    private User user;
    private RefreshToken activeToken;
    private RefreshToken revokedToken;

    @BeforeEach
    void setUp() {
        user = User.builder().username("johndoe")
                .email("john@example.com")
                .passwordHash("secret").build();
        entityManager.persistAndFlush(user);

        activeToken = new RefreshToken();
        activeToken.setUser(user);
        activeToken.setToken("active-token-123");
        activeToken.setIsRevoked(false);
        activeToken.setExpiresAt(LocalDateTime.now().plusDays(7));
        entityManager.persistAndFlush(activeToken);

        revokedToken = new RefreshToken();
        revokedToken.setUser(user);
        revokedToken.setToken("revoked-token-456");
        revokedToken.setIsRevoked(true);
        revokedToken.setRevokedAt(LocalDateTime.now().minusDays(1));
        revokedToken.setExpiresAt(LocalDateTime.now().plusDays(7));
        entityManager.persistAndFlush(revokedToken);
    }

    // --- findByToken ---

    @Test
    void findByToken_shouldReturnToken_whenTokenExists() {
        Optional<RefreshToken> result = refreshTokenRepository.findByToken("active-token-123");

        assertThat(result).isPresent();
        assertThat(result.get().getToken()).isEqualTo("active-token-123");
    }

    @Test
    void findByToken_shouldReturnEmpty_whenTokenNotExists() {
        Optional<RefreshToken> result = refreshTokenRepository.findByToken("unknown-token");

        assertThat(result).isEmpty();
    }

    // --- findByUserIdAndIsRevokedFalse ---

    @Test
    void findByUserIdAndIsRevokedFalse_shouldReturnOnlyActiveTokens() {
        List<RefreshToken> result = refreshTokenRepository
                .findByUserIdAndIsRevokedFalse(user.getId());

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getToken()).isEqualTo("active-token-123");
    }

    @Test
    void findByUserIdAndIsRevokedFalse_shouldReturnEmpty_whenAllTokensRevoked() {
        User otherUser = User.builder().username("janedoe")
                .email("jane@example.com").passwordHash("secret").build();
        entityManager.persistAndFlush(otherUser);

        RefreshToken token = new RefreshToken();
        token.setUser(otherUser);
        token.setToken("jane-revoked-token");
        token.setIsRevoked(true);
        token.setExpiresAt(LocalDateTime.now().plusDays(7));
        entityManager.persistAndFlush(token);

        List<RefreshToken> result = refreshTokenRepository
                .findByUserIdAndIsRevokedFalse(otherUser.getId());

        assertThat(result).isEmpty();
    }

    // --- revokeAllUserTokens ---

    @Test
    void revokeAllUserTokens_shouldRevokeAllActiveTokensForUser() {
        LocalDateTime revokedAt = LocalDateTime.now();
        refreshTokenRepository.revokeAllUserTokens(user.getId(), revokedAt);
        entityManager.clear();

        List<RefreshToken> result = refreshTokenRepository
                .findByUserIdAndIsRevokedFalse(user.getId());

        assertThat(result).isEmpty();
    }

    @Test
    void revokeAllUserTokens_shouldNotAffectOtherUsers() {
        User otherUser = User.builder().username("janedoe")
                .email("jane@example.com").passwordHash("secret").build();
        entityManager.persistAndFlush(otherUser);

        RefreshToken otherToken = new RefreshToken();
        otherToken.setUser(otherUser);
        otherToken.setToken("jane-active-token");
        otherToken.setIsRevoked(false);
        otherToken.setExpiresAt(LocalDateTime.now().plusDays(7));
        entityManager.persistAndFlush(otherToken);

        refreshTokenRepository.revokeAllUserTokens(user.getId(), LocalDateTime.now());
        entityManager.clear();

        List<RefreshToken> result = refreshTokenRepository
                .findByUserIdAndIsRevokedFalse(otherUser.getId());

        assertThat(result).hasSize(1);
    }

    // --- deleteExpiredToken ---

    @Test
    void deleteExpiredToken_shouldDeleteExpiredTokens() {
        RefreshToken expiredToken = new RefreshToken();
        expiredToken.setUser(user);
        expiredToken.setToken("expired-token-789");
        expiredToken.setIsRevoked(false);
        expiredToken.setExpiresAt(LocalDateTime.now().minusDays(1)); // already expired
        entityManager.persistAndFlush(expiredToken);

        refreshTokenRepository.deleteExpiredToken(LocalDateTime.now());
        entityManager.clear();

        Optional<RefreshToken> result = refreshTokenRepository.findByToken("expired-token-789");
        assertThat(result).isEmpty();
    }

    @Test
    void deleteExpiredToken_shouldNotDeleteNonExpiredTokens() {
        refreshTokenRepository.deleteExpiredToken(LocalDateTime.now());
        entityManager.clear();

        Optional<RefreshToken> result = refreshTokenRepository.findByToken("active-token-123");
        assertThat(result).isPresent();
    }

    // --- existsByTokenAndIsRevokedFalse ---

    @Test
    void existsByTokenAndIsRevokedFalse_shouldReturnTrue_whenTokenActiveExists() {
        assertThat(refreshTokenRepository
                .existsByTokenAndIsRevokedFalse("active-token-123")).isTrue();
    }

    @Test
    void existsByTokenAndIsRevokedFalse_shouldReturnFalse_whenTokenIsRevoked() {
        assertThat(refreshTokenRepository
                .existsByTokenAndIsRevokedFalse("revoked-token-456")).isFalse();
    }

    @Test
    void existsByTokenAndIsRevokedFalse_shouldReturnFalse_whenTokenNotExists() {
        assertThat(refreshTokenRepository
                .existsByTokenAndIsRevokedFalse("unknown-token")).isFalse();
    }
}
