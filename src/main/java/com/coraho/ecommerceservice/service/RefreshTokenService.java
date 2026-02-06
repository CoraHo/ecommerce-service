package com.coraho.ecommerceservice.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.coraho.ecommerceservice.DTO.AuthResponse;
import com.coraho.ecommerceservice.entity.RefreshToken;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.exception.RefreshTokenException;
import com.coraho.ecommerceservice.exception.ResourceNotFoundException;
import com.coraho.ecommerceservice.repository.RefreshTokenRepository;
import com.coraho.ecommerceservice.repository.UserRepository;
import com.coraho.ecommerceservice.security.JwtService;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    @Value("${security.jwt.refresh.expiration}")
    private long refreshTokenExpirationS;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    public RefreshToken createRefreshToken(Long userId, String ipAddress, String userAgent) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found"));

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiresAt(LocalDateTime.now().plusSeconds(refreshTokenExpirationS))
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    public AuthResponse refreshAccessToken(String refreshToken) {
        // Retrieve the RefreshToken from database
        RefreshToken existingRefreshToken = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new ResourceNotFoundException("Refresh Token not found"));

        // verify if the token is expired
        verifyExpiration(existingRefreshToken);
        User user = existingRefreshToken.getUser();

        // Generate a new JWT Access token
        Authentication authentication = getCurrentAuthentication();
        String newAccessToke = jwtService.generateToken(authentication);
        return AuthResponse.builder()
                .accessToken(newAccessToke)
                .refreshToken(refreshToken)
                .username(user.getUsername())
                .email(user.getEmail())
                .build();
    }

    @Transactional
    public void revokeToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new RefreshTokenException("Refresh token not found."));
        refreshToken.setIsRevoked(true);
        refreshToken.setRevokedAt(LocalDateTime.now());
        refreshTokenRepository.save(refreshToken);
    }

    @Transactional
    public void revokeAllUserTokens() {
        User user = getCurrentAuthenticatedUser();
        refreshTokenRepository.revokeAllUserTokens(user.getId(), LocalDateTime.now());
    }

    @Transactional
    public int deleteExpiredRefreshTokens() {
        List<RefreshToken> expiredRefreshTokens = refreshTokenRepository.findAll()
                .stream().filter(rt -> rt.getExpiresAt().isBefore(LocalDateTime.now()))
                .toList();
        refreshTokenRepository.deleteAll(expiredRefreshTokens);
        log.info("Deleted {} expired refresh tokens", expiredRefreshTokens.size());
        return expiredRefreshTokens.size();
    }

    public boolean isTokenValid(String token) {
        return refreshTokenRepository.existsByTokenAndIsRevokedFalse(token);
    }

    // helper methods

    private Authentication getCurrentAuthentication() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new InsufficientAuthenticationException("User not logged in");
        }
        return authentication;
    }

    private RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            refreshTokenRepository.delete(token);
            log.error("Refresh token expired.");
            throw new RefreshTokenException("Refresh token expired, please login again.");
        }

        // check if refresh token is revoked
        if (token.getIsRevoked()) {
            throw new RefreshTokenException("Refresh token has been revoked. Please login again");
        }
        return token;
    }

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

}
