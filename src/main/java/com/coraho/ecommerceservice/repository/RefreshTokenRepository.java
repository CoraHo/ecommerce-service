package com.coraho.ecommerceservice.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.coraho.ecommerceservice.entity.RefreshToken;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    List<RefreshToken> findByUserIdAndIsRevokedFalse(Long userId);

    @Modifying
    @Query("""
            UPDATE RefreshToken rt
            SET rt.isRevoked = true, rt.revokedAt = :revokedAt
            WHERE rt.user.id=:userId
            """)
    void revokeAllUserTokens(@Param("userId") Long userId, @Param("revokedAt") LocalDateTime revokedAt);

    @Modifying
    @Query("""
            DELETE FROM RefreshToken rt
            WHERE rt.expiresAt < :now
            """)
    void deleteExpiredToken(@Param("now") LocalDateTime now);

    boolean existsByTokenAndIsRevokedFlase(String token);

}
