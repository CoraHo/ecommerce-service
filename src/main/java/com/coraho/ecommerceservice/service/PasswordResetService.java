package com.coraho.ecommerceservice.service;

import java.security.Key;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Optional;

import com.coraho.ecommerceservice.DTO.PasswordResetRequest;
import com.coraho.ecommerceservice.DTO.ResetPasswordWithTokenRequest;
import com.coraho.ecommerceservice.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
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

import javax.crypto.SecretKey;

@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordResetService {
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final EmailService emailService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

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
    public void resetPasswordWithCurrentPassword(PasswordResetRequest request, String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // verify the current password is correct
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
            throw new IllegalArgumentException("Password is incorrect");
        }

        // reset the password
        resetPassword(user, request.getNewPassword());

    }

    @Transactional
    public void forgotPassword(String email) {
        // verify if user exists in database, valid, and non-locked
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        if (!user.getIsActive()) {
            throw new DisabledException("Account is disabled");
        }
        if (user.getIsLocked()) {
            throw new LockedException("Account is locked");
        }

        // generate password reset token and send password reset email
        createAndSendPasswordResetToken(user);
    }

    private void createAndSendPasswordResetToken(User user) {
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
        String verificationLink = emailBaseUrl + "/api/auth/validate-reset-password-token?token="
                + passwordResetToken;

        emailService.sendPasswordResetEmail(user.getEmail(), user.getFirstName(), verificationLink);
    }

    @Transactional
    public void validatePasswordResetToken(String token) {
        validateTokenAndUser(token); // Extract common logic
        log.info("Password reset token is verified successfully");
    }

    @Transactional
    public String resetPasswordWithToken(ResetPasswordWithTokenRequest request) {
        User user = validateTokenAndUser(request.getToken()); // Extract common logic
        log.info("Password reset token is verified successfully");

        // reset password
        resetPassword(user, request.getNewPassword());

        // ONLY mark token as used AFTER password successfully changed
        PasswordResetToken passwordResetToken = passwordResetTokenRepository
                .findByTokenAndIsUsedFalse(request.getToken())
                .orElseThrow(() -> new PasswordResetTokenException("Password reset token not found"));

        passwordResetToken.setIsUsed(true);
        passwordResetToken.setUsedAt(LocalDateTime.now());
        passwordResetTokenRepository.save(passwordResetToken);

        log.info("Password reset successfully for user: {}", user.getEmail());
        return user.getEmail();
    }

    private void resetPassword(User user, String newPassword) {
        // validate new password requirements
        String passwordRegex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{6,}$";
        if (!newPassword.matches(passwordRegex)) {
            throw new IllegalArgumentException(
                    "Password must be at least 6 characters and contain at least one uppercase letter, " +
                            "one lowercase letter, and one digit");
        }

        // ensure new password is different
        if (passwordEncoder.matches(newPassword, user.getPasswordHash())) {
            throw new IllegalArgumentException("New password must be different from current password");
        }

        // reset the password
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // send confirmation email OUTSIDE transaction or handle failure gracefully
        try {
            emailService.sendPasswordResetConfirmationEmail(user.getEmail(), user.getFirstName());
        } catch (Exception e) {
            // Log the error but don't fail the password reset
            log.error("Failed to send password reset confirmation email", e);
        }
    }

    private User validateTokenAndUser(String token) {
        // 1. Retrieve token from database
        PasswordResetToken passwordResetToken = passwordResetTokenRepository
                .findByTokenAndIsUsedFalse(token)
                .orElseThrow(() -> new PasswordResetTokenException("Password reset token not found"));

        // 2. Check if token is expired
        if (passwordResetToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new PasswordResetTokenException("Password reset token has expired");
        }

        // 3. Verify JWT signature and parse claims
        Claims claims;
        try {
            claims = Jwts.parser()
                    .verifyWith((SecretKey) getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException e) {
            throw new PasswordResetTokenException("Invalid password reset token");
        }

        // 4. Extract user email and verify user exists
        String email = claims.getSubject();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // 5. Verify account status
        if (!user.getIsActive()) {
            throw new DisabledException("Account is disabled");
        }
        if (user.getIsLocked()) {
            throw new LockedException("Account is locked");
        }

        return user; // Return user for reset method
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
