package com.coraho.ecommerceservice.service;

import java.security.Key;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import com.coraho.ecommerceservice.entity.EmailVerificationToken;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.exception.EmailVerificationException;
import com.coraho.ecommerceservice.repository.EmailVerificationTokenRepository;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EmailVerificationTokenService {
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final EmailService emailService;

    @Value("${app.email.verification.token.expiration}")
    private long emailVerificationTokenExpiryMS;

    @Value("${app.email.verification.base-url}")
    private String emailVerificationBaseUrl;

    @Value("${app.email.secret-key}")
    private String emailVerificationTokenSecretKey;

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(emailVerificationTokenSecretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    @Transactional
    public void createAndSendEmailVerificationToken(User user) {
        // avoid resue and manual replay
        if (user.getIsEmailVerified()) {
            throw new EmailVerificationException("This Email has already been verified");
        }

        // add a cooldown to prevent repeat and frequent request

        // invalidate any existing tokens
        emailVerificationTokenRepository.findByUserIdAndIsVerifiedFalse(user.getId())
                .forEach(token -> {
                    token.setIsVerified(true);
                    token.setVerifiedAt(LocalDateTime.now());
                    emailVerificationTokenRepository.save(token);
                });

        String token = generateEmailVerificationToken(user.getEmail());

        EmailVerificationToken emailVerificationToken = EmailVerificationToken.builder()
                .user(user)
                .token(token)
                .expiresAt(LocalDateTime.now().plusSeconds(emailVerificationTokenExpiryMS))
                .build();

        emailVerificationTokenRepository.save(emailVerificationToken);

        // send email
        String verificationLink = emailVerificationBaseUrl + "/api/v1/auth/verify-email?token="
                + emailVerificationToken;
        emailService.sendVerificationEmail(user.getEmail(), user.getFirstName(), verificationLink);
    }

    private String generateEmailVerificationToken(String email) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + emailVerificationTokenExpiryMS);

        return Jwts.builder()
                .subject(email) // returns email
                .claim("Purpose", "email verifictaion")
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey()) // default HS512 encoding algorithm
                .compact();
    }

}
