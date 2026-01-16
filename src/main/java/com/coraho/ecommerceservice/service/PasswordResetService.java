package com.coraho.ecommerceservice.service;

import java.security.Key;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.coraho.ecommerceservice.entity.PasswordResetToken;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.exception.PasswordResetTokenException;
import com.coraho.ecommerceservice.repository.PasswordResetTokenRepository;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class PasswordResetService {
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final EmailService emailService;

    @Value("${app.password.reset.token.expiration}")
    private long passwordResetTokenExpiryS;

    @Value("${app.password.reset.secret-key}")
    private String passwordResetTokenSecretKey;

    @Value("${app.email.base-url}")
    private String emailBaseUrl;

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(passwordResetTokenSecretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    @Transactional
    public void createAndSendPasswordResetToken(User user) {
        // check the resent token generated
        // add a cool down to present repeat and frequent requests
        Optional<PasswordResetToken> recentToken = passwordResetTokenRepository.findByUserIdAndIsUsedFalse(user.getId())
                .stream().filter(token -> token.getExpiresAt().isAfter(LocalDateTime.now().plusMinutes(5)))
                .findFirst();

        if (recentToken.isPresent()) {
            throw new PasswordResetTokenException("Please wait before requesting another password reset email");
        }

        // invalidate all existing tokens
        passwordResetTokenRepository.findByUserIdAndIsUsedFalse(user.getId())
                .forEach(token -> {
                    token.setIsUsed(true);
                    token.setUsedAt(LocalDateTime.now());
                    passwordResetTokenRepository.save(token);
                });

        // generate a new JWT token
        String token = generatePasswordResetToken(user.getEmail());

        // store the token into database
        PasswordResetToken passwordResetToken = PasswordResetToken.builder()
                .user(user)
                .token(token)
                .expiresAt(LocalDateTime.now().plusSeconds(passwordResetTokenExpiryS))
                .build();

        passwordResetTokenRepository.save(passwordResetToken);

        // send email
        String verificationLink = emailBaseUrl + "/api/auth/reset-password?token="
                + passwordResetToken;

        emailService.sendPasswrodResetEmail(user.getEmail(), user.getFirstName(), verificationLink);

    }

    private String generatePasswordResetToken(String email) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + (passwordResetTokenExpiryS));

        return Jwts.builder()
                .subject(email)
                .claim("Purpose", "Reset Password")
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey())
                .compact();
    }
}
