package com.coraho.ecommerceservice.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.coraho.ecommerceservice.entity.EmailVerificationToken;

@Repository
public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Long> {

    Optional<EmailVerificationToken> findbyTokenAndIsVerifiedFalse(String token);

    List<EmailVerificationToken> findByUserIdAndIsVerifiedFalse(Long userId);

}
