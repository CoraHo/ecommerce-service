package com.coraho.ecommerceservice.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import com.coraho.ecommerceservice.entity.EmailVerificationToken;
import com.coraho.ecommerceservice.entity.User;

@DataJpaTest(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
@DisplayName("EmailVerificationTokenRepository Tests")
public class EmailVerificationTokenRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private EmailVerificationTokenRepository emailVerificationTokenRepository;

    private User user;
    private EmailVerificationToken verifiedToken;
    private EmailVerificationToken unverifiedToken;

    @BeforeEach
    void setUp() {
        user = User.builder().username("johndoe")
                .email("john@example.com")
                .passwordHash("secret").build();
        entityManager.persistAndFlush(user);

        unverifiedToken = new EmailVerificationToken();
        unverifiedToken.setUser(user);
        unverifiedToken.setToken("unverified-token-123");
        unverifiedToken.setIsVerified(false);
        unverifiedToken.setExpiresAt(LocalDateTime.now().plusHours(24));
        entityManager.persistAndFlush(unverifiedToken);

        verifiedToken = new EmailVerificationToken();
        verifiedToken.setUser(user);
        verifiedToken.setToken("verified-token-456");
        verifiedToken.setIsVerified(true);
        verifiedToken.setExpiresAt(LocalDateTime.now().plusHours(24));
        entityManager.persistAndFlush(verifiedToken);

    }

    // --- findByTokenAndIsVerifiedFalse ---

    @Test
    void findByTokenAndIsVerifiedFalse_shouldReturnToken_whenTokenExistsAndNotVerified() {
        Optional<EmailVerificationToken> result = emailVerificationTokenRepository
                .findByTokenAndIsVerifiedFalse("unverified-token-123");

        assertThat(result).isPresent();
        assertThat(result.get().getToken()).isEqualTo("unverified-token-123");
    }

    @Test
    void findByTokenAndIsVerifiedFalse_shouldReturnEmpty_whenTokenIsAlreadyVerified() {
        Optional<EmailVerificationToken> result = emailVerificationTokenRepository
                .findByTokenAndIsVerifiedFalse("verified-token-456");

        assertThat(result).isEmpty();
    }

    @Test
    void findByTokenAndIsVerifiedFalse_shouldReturnEmpty_whenTokenNotExists() {
        Optional<EmailVerificationToken> result = emailVerificationTokenRepository
                .findByTokenAndIsVerifiedFalse("unknown-token");

        assertThat(result).isEmpty();
    }

    // --- findByUserIdAndIsVerifiedFalse ---

    @Test
    void findByUserIdAndIsVerifiedFalse_shouldReturnOnlyUnverifiedTokens() {
        List<EmailVerificationToken> result = emailVerificationTokenRepository
                .findByUserIdAndIsVerifiedFalse(user.getId());

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getToken()).isEqualTo("unverified-token-123");
    }

    @Test
    void findByUserIdAndIsVerifiedFalse_shouldReturnEmpty_whenAllTokensVerified() {
        User otherUser = User.builder().username("janedoe")
                .email("jane@example.com").passwordHash("secret").build();
        entityManager.persistAndFlush(otherUser);

        EmailVerificationToken token = new EmailVerificationToken();
        token.setUser(otherUser);
        token.setToken("jane-verified-token");
        token.setIsVerified(true);
        token.setExpiresAt(LocalDateTime.now().plusHours(24));
        entityManager.persistAndFlush(token);

        List<EmailVerificationToken> result = emailVerificationTokenRepository
                .findByUserIdAndIsVerifiedFalse(otherUser.getId());

        assertThat(result).isEmpty();
    }

    @Test
    void findByUserIdAndIsVerifiedFalse_shouldReturnEmpty_whenUserHasNoTokens() {
        User otherUser = User.builder().username("janedoe")
                .email("jane@example.com").passwordHash("secret").build();
        entityManager.persistAndFlush(otherUser);

        List<EmailVerificationToken> result = emailVerificationTokenRepository
                .findByUserIdAndIsVerifiedFalse(otherUser.getId());

        assertThat(result).isEmpty();
    }

    @Test
    void findByUserIdAndIsVerifiedFalse_shouldNotReturnTokensBelongingToOtherUsers() {
        User otherUser = User.builder().username("janedoe")
                .email("jane@example.com").passwordHash("secret").build();
        entityManager.persistAndFlush(otherUser);

        EmailVerificationToken otherToken = new EmailVerificationToken();
        otherToken.setUser(otherUser);
        otherToken.setToken("jane-unverified-token");
        otherToken.setIsVerified(false);
        otherToken.setExpiresAt(LocalDateTime.now().plusHours(24));
        entityManager.persistAndFlush(otherToken);

        List<EmailVerificationToken> result = emailVerificationTokenRepository
                .findByUserIdAndIsVerifiedFalse(user.getId());

        assertThat(result).allMatch(t -> t.getUser().getId().equals(user.getId()));
    }
}
