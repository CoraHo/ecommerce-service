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

import com.coraho.ecommerceservice.entity.LoginAttempt;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.entity.LoginAttempt.AttemptResult;

@DataJpaTest(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
@DisplayName("LoginAttemptRepository Tests")
public class LoginAttemptRepositoryTest {
    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private LoginAttemptRepository loginAttemptRepository;

    private User user;
    private final LocalDateTime now = LocalDateTime.now();
    private final LocalDateTime oneHourAgo = now.minusHours(1);
    private final LocalDateTime twoHoursAgo = now.minusHours(2);

    @BeforeEach
    void setUp() {
        user = User.builder().username("johndoe")
                .email("john@example.com")
                .passwordHash("secret").build();
        entityManager.persistAndFlush(user);
    }

    private void insertAttempt(String email, String ip, String result, LocalDateTime attemptedAt) {
        entityManager.getEntityManager().createNativeQuery("""
                INSERT INTO login_attempts (user_id, email, ip_address, attempt_result, attempted_at)
                VALUES (?, ?, ?, ?, ?)
                """)
                .setParameter(1, user.getId())
                .setParameter(2, email)
                .setParameter(3, ip)
                .setParameter(4, result)
                .setParameter(5, attemptedAt)
                .executeUpdate();
    }

    // --- countFailedLoginsByEmailAndSince ---

    @Test
    void countFailedLoginsByEmailAndSince_shouldCountOnlyFailedAttemptsAfterSince() {
        insertAttempt("john@example.com", "192.168.1.1", AttemptResult.FAILED.getValue(), now.minusMinutes(10));
        insertAttempt("john@example.com", "192.168.1.1", AttemptResult.FAILED.getValue(), now.minusMinutes(20));
        // should not count
        insertAttempt("john@example.com", "192.168.1.1", AttemptResult.SUCCESS.getValue(), now.minusMinutes(5));
        // outside window, should not count
        insertAttempt("john@example.com", "192.168.1.1", AttemptResult.FAILED.getValue(), twoHoursAgo);

        long count = loginAttemptRepository
                .countFailedLoginsByEmailAndSince("john@example.com", oneHourAgo);

        assertThat(count).isEqualTo(2);
    }

    @Test
    void countFailedLoginsByEmailAndSince_shouldReturnZero_whenNoFailedAttempts() {
        insertAttempt("john@example.com", "192.168.1.1", AttemptResult.SUCCESS.getValue(), now.minusMinutes(10));

        long count = loginAttemptRepository
                .countFailedLoginsByEmailAndSince("john@example.com", oneHourAgo);

        assertThat(count).isZero();
    }

    @Test
    void countFailedLoginsByEmailAndSince_shouldNotCountOtherEmails() {
        insertAttempt("other@example.com", "192.168.1.1", AttemptResult.FAILED.getValue(), now.minusMinutes(10));

        long count = loginAttemptRepository
                .countFailedLoginsByEmailAndSince("john@example.com", oneHourAgo);

        assertThat(count).isZero();
    }

    // --- countFailedLoginsByIpAddressAndSince ---

    @Test
    void countFailedLoginsByIpAddressAndSince_shouldCountOnlyFailedAttemptsAfterSince() {
        insertAttempt("john@example.com", "10.0.0.1", AttemptResult.FAILED.getValue(), now.minusMinutes(10));
        insertAttempt("john@example.com", "10.0.0.1", AttemptResult.FAILED.getValue(), now.minusMinutes(30));
        insertAttempt("john@example.com", "10.0.0.1", AttemptResult.SUCCESS.getValue(), now.minusMinutes(5)); // should
                                                                                                              // not
        // count
        insertAttempt("john@example.com", "10.0.0.1", AttemptResult.FAILED.getValue(), twoHoursAgo); // outside window

        long count = loginAttemptRepository
                .countFailedLoginsByIpAddressAndSince("10.0.0.1", oneHourAgo);

        assertThat(count).isEqualTo(2);
    }

    @Test
    void countFailedLoginsByIpAddressAndSince_shouldNotCountOtherIpAddresses() {
        insertAttempt("john@example.com", "10.0.0.2", AttemptResult.FAILED.getValue(), now.minusMinutes(10));

        long count = loginAttemptRepository
                .countFailedLoginsByIpAddressAndSince("10.0.0.1", oneHourAgo);

        assertThat(count).isZero();
    }

    // --- findByUserIdOrderByAttemptedAtDesc ---

    @Test
    void findByUserIdOrderByAttemptedAtDesc_shouldReturnAttemptsInDescendingOrder() {
        insertAttempt("john@example.com", "10.0.0.1", AttemptResult.FAILED.getValue(), now.minusMinutes(30));
        insertAttempt("john@example.com", "10.0.0.1", AttemptResult.SUCCESS.getValue(), now.minusMinutes(10));
        insertAttempt("john@example.com", "10.0.0.1", AttemptResult.FAILED.getValue(), now.minusMinutes(20));

        List<LoginAttempt> result = loginAttemptRepository
                .findByUserIdOrderByAttemptedAtDesc(user.getId());

        assertThat(result).hasSize(3);
        assertThat(result.get(0).getAttemptedAt())
                .isAfter(result.get(1).getAttemptedAt());
        assertThat(result.get(1).getAttemptedAt())
                .isAfter(result.get(2).getAttemptedAt());
    }

    @Test
    void findByUserIdOrderByAttemptedAtDesc_shouldReturnEmpty_whenUserHasNoAttempts() {
        List<LoginAttempt> result = loginAttemptRepository
                .findByUserIdOrderByAttemptedAtDesc(user.getId());

        assertThat(result).isEmpty();
    }

    // --- findByEmailOrderByAttemptedAtDesc ---

    @Test
    void findByEmailOrderByAttemptedAtDesc_shouldReturnAttemptsInDescendingOrder() {
        insertAttempt("john@example.com", "10.0.0.1", AttemptResult.FAILED.getValue(), now.minusMinutes(30));
        insertAttempt("john@example.com", "10.0.0.1", AttemptResult.SUCCESS.getValue(), now.minusMinutes(10));

        List<LoginAttempt> result = loginAttemptRepository
                .findByEmailOrderByAttemptedAtDesc("john@example.com");

        assertThat(result).hasSize(2);
        assertThat(result.get(0).getAttemptedAt())
                .isAfter(result.get(1).getAttemptedAt());
    }

    @Test
    void findByEmailOrderByAttemptedAtDesc_shouldNotReturnOtherEmails() {
        insertAttempt("other@example.com", "10.0.0.1", AttemptResult.FAILED.getValue(), now.minusMinutes(10));

        List<LoginAttempt> result = loginAttemptRepository
                .findByEmailOrderByAttemptedAtDesc("john@example.com");

        assertThat(result).isEmpty();
    }

    // --- countDistinctEmailByIpAddressSince (credential stuffing detection) ---

    @Test
    void countDistinctEmailByIpAddressSince_shouldCountDistinctEmailsFromSameIp() {
        insertAttempt("john@example.com", "10.0.0.1", AttemptResult.FAILED.getValue(), now.minusMinutes(10));
        insertAttempt("alice@example.com", "10.0.0.1", AttemptResult.FAILED.getValue(), now.minusMinutes(15));
        insertAttempt("bob@example.com", "10.0.0.1", AttemptResult.FAILED.getValue(), now.minusMinutes(20));
        insertAttempt("john@example.com", "10.0.0.1", AttemptResult.FAILED.getValue(), now.minusMinutes(25)); // duplicate
        // email

        long count = loginAttemptRepository
                .countDistinctEmailByIpAddressSince("10.0.0.1", oneHourAgo);

        assertThat(count).isEqualTo(3); // john, alice, bob
    }

    @Test
    void countDistinctEmailByIpAddressSince_shouldNotCountAttemptsOutsideWindow() {
        insertAttempt("john@example.com", "10.0.0.1", AttemptResult.FAILED.getValue(), twoHoursAgo);
        insertAttempt("alice@example.com", "10.0.0.1", AttemptResult.FAILED.getValue(), now.minusMinutes(10));

        long count = loginAttemptRepository
                .countDistinctEmailByIpAddressSince("10.0.0.1", oneHourAgo);

        assertThat(count).isEqualTo(1); // only alice
    }

    // --- countDistincIPAddressByEmailSince (account takeover detection) ---

    @Test
    void countDistinctIPAddressByEmailSince_shouldCountDistinctIpsForSameEmail() {
        insertAttempt("john@example.com", "10.0.0.1", AttemptResult.FAILED.getValue(), now.minusMinutes(10));
        insertAttempt("john@example.com", "10.0.0.2", AttemptResult.FAILED.getValue(), now.minusMinutes(15));
        insertAttempt("john@example.com", "10.0.0.3", AttemptResult.FAILED.getValue(), now.minusMinutes(20));
        insertAttempt("john@example.com", "10.0.0.1", AttemptResult.FAILED.getValue(), now.minusMinutes(25)); // duplicate
                                                                                                              // IP

        long count = loginAttemptRepository
                .countDistincIPAddressByEmailSince("john@example.com", oneHourAgo);

        assertThat(count).isEqualTo(3); // .1, .2, .3
    }

    @Test
    void countDistinctIPAddressByEmailSince_shouldNotCountAttemptsOutsideWindow() {
        insertAttempt("john@example.com", "10.0.0.1", AttemptResult.FAILED.getValue(), twoHoursAgo);
        insertAttempt("john@example.com", "10.0.0.2", AttemptResult.FAILED.getValue(), now.minusMinutes(10));

        long count = loginAttemptRepository
                .countDistincIPAddressByEmailSince("john@example.com", oneHourAgo);

        assertThat(count).isEqualTo(1); // only .2
    }

    // --- existsByUserIdAndIpAddressAndAttemptResult ---

    @Test
    void existsByUserIdAndIpAddressAndAttemptResult_shouldReturnTrue_whenMatchExists() {
        insertAttempt("john@example.com", "10.0.0.1", AttemptResult.SUCCESS.getValue(), now.minusMinutes(10));

        assertThat(loginAttemptRepository
                .existsByUserIdAndIpAddressAndAttemptResult(
                        user.getId(), "10.0.0.1", AttemptResult.SUCCESS))
                .isTrue();
    }

    @Test
    void existsByUserIdAndIpAddressAndAttemptResult_shouldReturnFalse_whenResultDoesNotMatch() {
        insertAttempt("john@example.com", "10.0.0.1", AttemptResult.FAILED.getValue(), now.minusMinutes(10));

        assertThat(loginAttemptRepository
                .existsByUserIdAndIpAddressAndAttemptResult(
                        user.getId(), "10.0.0.1", AttemptResult.SUCCESS))
                .isFalse();
    }

    @Test
    void existsByUserIdAndIpAddressAndAttemptResult_shouldReturnFalse_whenIpDoesNotMatch() {
        insertAttempt("john@example.com", "10.0.0.2", AttemptResult.SUCCESS.getValue(), now.minusMinutes(10));

        assertThat(loginAttemptRepository
                .existsByUserIdAndIpAddressAndAttemptResult(
                        user.getId(), "10.0.0.1", AttemptResult.SUCCESS))
                .isFalse();
    }
}
