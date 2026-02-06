package com.coraho.ecommerceservice.service;

import java.security.Key;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.coraho.ecommerceservice.entity.EmailVerificationToken;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.exception.EmailVerificationException;
import com.coraho.ecommerceservice.repository.EmailVerificationTokenRepository;
import com.coraho.ecommerceservice.repository.UserRepository;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailVerificationTokenService {
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final EmailService emailService;
    private final UserRepository userRepository;

    @Value("${app.email.verification.token.expiration}")
    private long emailVerificationTokenExpiryS;

    @Value("${app.email.base-url}")
    private String emailBaseUrl;

    @Value("${app.email.secret-key}")
    private String emailVerificationTokenSecretKey;

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(emailVerificationTokenSecretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // For the first request and following requests after validation
    @Transactional
    public void createAndSendEmailVerificationToken(User user) {
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
                .expiresAt(LocalDateTime.now().plusSeconds(emailVerificationTokenExpiryS))
                .build();

        emailVerificationTokenRepository.save(emailVerificationToken);

        // send email
        String verificationLink = emailBaseUrl + "/api/auth/verify-email?token="
                + emailVerificationToken;
        emailService.sendVerificationEmail(user.getEmail(), user.getFirstName(), verificationLink);
    }

    @Transactional
    public void verifyEmail(String token) {
        // find the token in database
        EmailVerificationToken emailVerificationToken = emailVerificationTokenRepository
                .findByTokenAndIsVerifiedFalse(token)
                .orElseThrow(() -> new EmailVerificationException("Invalid verification token"));

        // check if token is expired
        if (emailVerificationToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new EmailVerificationException("Verification token has expired");
        }

        // get the user from JWT token claims and check if the user is already verified
        Claims claims = Jwts.parser()
                .verifyWith((SecretKey) getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        String email = claims.getSubject();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        if (user.getIsEmailVerified()) {
            throw new EmailVerificationException("Email is already verified");
        }

        // mark token is verified and make user is verified
        emailVerificationToken.setIsVerified(true);
        emailVerificationTokenRepository.save(emailVerificationToken);
        user.setIsEmailVerified(true);
        userRepository.save(user);

        log.info("Email is verified successfully for user: {}", email);
    }

    @Transactional
    public void resendVerificationEmail() {
        User user = getCurrentAuthenticatedUser();

        // avoid resue and manual replay
        if (user.getIsEmailVerified()) {
            throw new EmailVerificationException("This Email has already been verified");
        }

        // check for recent tokens and add a cooldown to prevent repeat and frequent
        // request
        Optional<EmailVerificationToken> recentToken = emailVerificationTokenRepository
                .findByUserIdAndIsVerifiedFalse(user.getId()).stream()
                .filter(token -> token.getCreatedAt().isAfter(LocalDateTime.now().minusMinutes(5)))
                .findFirst();
        if (recentToken.isPresent()) {
            throw new EmailVerificationException("Please wait before requesting another verification email");
        }

        // create a new token and send email
        createAndSendEmailVerificationToken(user);
    }

    public int deleteExpiredEmailVerificationTokens() {
        List<EmailVerificationToken> expiredTokens = emailVerificationTokenRepository.findAll()
                .stream().filter(token -> token.getCreatedAt().isBefore(LocalDateTime.now()))
                .toList();
        emailVerificationTokenRepository.deleteAll(expiredTokens);
        log.info("Deleted {} expired Email verification tokens", expiredTokens.size());
        return expiredTokens.size();
    }

    // helper methods

    private User getCurrentAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new InsufficientAuthenticationException("User not logged in");
        }
        String email = authentication.getName();
        User currentUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return currentUser;
    }

    private String generateEmailVerificationToken(String email) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + emailVerificationTokenExpiryS);

        return Jwts.builder()
                .subject(email) // returns email
                .claim("Purpose", "email verifictaion")
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey()) // default HS512 encoding algorithm
                .compact();
    }

}
