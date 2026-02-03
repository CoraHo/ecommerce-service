package com.coraho.ecommerceservice.repository;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.coraho.ecommerceservice.entity.LoginAttempt;
import com.coraho.ecommerceservice.entity.LoginAttempt.AttemptResult;

@Repository
public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {

        /* Count failed login attempts for a specific email within a time window */
        @Query("""
                        SELECT COUNT(la) FROM LoginAttempt la
                        WHERE la.email= :email
                        AND la.attemptResult = 'FAILED'
                        AND la.attemptedAt > :since
                        """)
        long countFailedLoginsByEmailAndSince(@Param("email") String email, @Param("since") LocalDateTime since);

        @Query("""
                        SELECT COUNT(la) FROM LoginAttempt la
                        WHERE la.ipAddress = :ipAddress
                        AND la.attemptResult = 'FAILED'
                        AND la.attemptedAt > :since
                        """)
        long countFailedLoginsByIpAddressAndSince(@Param("ipAddress") String ipAddress,
                        @Param("since") LocalDateTime since);

        /* Find all login attempts for a user */
        List<LoginAttempt> findByUserIdOrderByAttemptedAtDesc(Long userId);

        /* Find all login attempts by email */
        List<LoginAttempt> findByEmailOrderByAttemptedAtDesc(String email);

        /* Find all failed login attemps */

        /*
         * Check if there are credential stuffing patterns - multiple different emails
         * from same IP
         */
        @Query("""
                        SELECT COUNT(DISTINCT la.email) FROM LoginAttempt la
                        WHERE la.ipAddress = :ipAddress
                        AND la.attemptedAt > :since
                        """)
        long countDistinctEmailByIpAddressSince(@Param("ipAddress") String ipAddress,
                        @Param("since") LocalDateTime since);

        /*
         * Check if there are accont takeover patterns - recent login attempts from
         * different IPs for same email
         */
        @Query("""
                        SELECT COUNT(DISTINCT la.ipAddress) FROM LoginAttempt la
                        WHERE la.email = :email
                        AND la.attemptedAt > :since
                        """)
        long countDistincIPAddressByEmailSince(@Param("email") String email, @Param("since") LocalDateTime since);

        boolean existsByUserIdAndIpAddressAndAttemptResult(Long userId, String ipAddress, AttemptResult attemptResult);

}
