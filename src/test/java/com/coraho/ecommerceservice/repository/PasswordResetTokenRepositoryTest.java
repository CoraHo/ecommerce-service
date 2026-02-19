package com.coraho.ecommerceservice.repository;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDateTime;
import java.util.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import com.coraho.ecommerceservice.entity.PasswordResetToken;
import com.coraho.ecommerceservice.entity.User;

@DataJpaTest(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
@DisplayName("PasswordResetTokenRepository Tests")
public class PasswordResetTokenRepositoryTest {
    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;

    private User user;
    private PasswordResetToken unusedToken;
    private PasswordResetToken usedToken;

    @BeforeEach
    void setUp() {
        user = User.builder().username("johndoe")
                .email("john@example.com")
                .passwordHash("secret").build();
        entityManager.persistAndFlush(user);

        unusedToken = new PasswordResetToken();
        unusedToken.setUser(user);
        unusedToken.setToken("unused-token-123");
        unusedToken.setIsUsed(false);
        unusedToken.setExpiresAt(LocalDateTime.now().plusHours(1));
        entityManager.persistAndFlush(unusedToken);

        usedToken = new PasswordResetToken();
        usedToken.setUser(user);
        usedToken.setToken("used-token-456");
        usedToken.setIsUsed(true);
        usedToken.setExpiresAt(LocalDateTime.now().plusHours(1));
        entityManager.persistAndFlush(usedToken);
    }

    // --- findByTokenAndIsUsedFalse ---

    @Test
    void findByTokenAndIsUsedFalse_shouldReturnToken_whenTokenExistsAndNotUsed() {
        Optional<PasswordResetToken> result = passwordResetTokenRepository
                .findByTokenAndIsUsedFalse("unused-token-123");

        assertThat(result).isPresent();
        assertThat(result.get().getToken()).isEqualTo("unused-token-123");
    }

    @Test
    void findByTokenAndIsUsedFalse_shouldReturnEmpty_whenTokenIsUsed() {
        Optional<PasswordResetToken> result = passwordResetTokenRepository
                .findByTokenAndIsUsedFalse("used-token-456");

        assertThat(result).isEmpty();
    }

    @Test
    void findByTokenAndIsUsedFalse_shouldReturnEmpty_whenTokenNotExists() {
        Optional<PasswordResetToken> result = passwordResetTokenRepository
                .findByTokenAndIsUsedFalse("unknown-token");

        assertThat(result).isEmpty();
    }

    // --- findByUserIdAndIsUsedFalse ---

    @Test
    void findByUserIdAndIsUsedFalse_shouldReturnOnlyUnusedTokens() {
        List<PasswordResetToken> result = passwordResetTokenRepository
                .findByUserIdAndIsUsedFalse(user.getId());

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getToken()).isEqualTo("unused-token-123");
    }

    @Test
    void findByUserIdAndIsUsedFalse_shouldReturnEmpty_whenAllTokensUsed() {
        User otherUser = User.builder().username("janedoe")
                .email("jane@example.com").passwordHash("secret").build();
        entityManager.persistAndFlush(otherUser);

        PasswordResetToken token = new PasswordResetToken();
        token.setUser(otherUser);
        token.setToken("jane-used-token");
        token.setIsUsed(true);
        token.setExpiresAt(LocalDateTime.now().plusHours(1));
        entityManager.persistAndFlush(token);

        List<PasswordResetToken> result = passwordResetTokenRepository
                .findByUserIdAndIsUsedFalse(otherUser.getId());

        assertThat(result).isEmpty();
    }

    @Test
    void findByUserIdAndIsUsedFalse_shouldReturnEmpty_whenUserHasNoTokens() {
        User otherUser = User.builder().username("janedoe")
                .email("jane@example.com").passwordHash("secret").build();
        entityManager.persistAndFlush(otherUser);

        List<PasswordResetToken> result = passwordResetTokenRepository
                .findByUserIdAndIsUsedFalse(otherUser.getId());

        assertThat(result).isEmpty();
    }

    @Test
    void findByUserIdAndIsUsedFalse_shouldNotReturnTokensBelongingToOtherUsers() {
        User otherUser = User.builder().username("janedoe")
                .email("jane@example.com").passwordHash("secret").build();
        entityManager.persistAndFlush(otherUser);

        PasswordResetToken otherToken = new PasswordResetToken();
        otherToken.setUser(otherUser);
        otherToken.setToken("jane-unused-token");
        otherToken.setIsUsed(false);
        otherToken.setExpiresAt(LocalDateTime.now().plusHours(1));
        entityManager.persistAndFlush(otherToken);

        List<PasswordResetToken> result = passwordResetTokenRepository
                .findByUserIdAndIsUsedFalse(user.getId());

        assertThat(result).allMatch(t -> t.getUser().getId().equals(user.getId()));
    }
}
