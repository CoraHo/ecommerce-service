package com.coraho.ecommerceservice.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.coraho.ecommerceservice.DTO.LoginRequest;
import com.coraho.ecommerceservice.DTO.AuthResponse;
import com.coraho.ecommerceservice.DTO.RegisterRequest;
import com.coraho.ecommerceservice.DTO.RegisterResponse;
import com.coraho.ecommerceservice.entity.RefreshToken;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.repository.UserRepository;
import com.coraho.ecommerceservice.security.JwtService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final EmailVerificationTokenService emailVerificationTokenService;

    public RegisterResponse signup(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email already exists");
        }
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("Username already exists");
        }

        User user = User.builder()
                .email(request.getEmail())
                .username(request.getUsername())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .build();
        User savedUser = userRepository.save(user);

        // send the verification email once the user is created
        emailVerificationTokenService.createAndSendEmailVerificationToken(savedUser);

        RegisterResponse registerResponse = RegisterResponse.builder()
                .id(savedUser.getId())
                .email(savedUser.getEmail())
                .username(savedUser.getUsername())
                .username(savedUser.getUsername())
                .firstName(savedUser.getFirstName())
                .lastName(savedUser.getLastName())
                .isActive(savedUser.getIsActive())
                .isEmailVerified(savedUser.getIsEmailVerified())
                .isLocked(savedUser.getIsLocked())
                .createdAt(savedUser.getCreatedAt())
                .build();

        return registerResponse;
    }

    public AuthResponse authenticate(LoginRequest request, String ipAddress, String userAgent) {
        Authentication authentication = authenticationManager
                .authenticate(
                        new UsernamePasswordAuthenticationToken(request.getUsernameOrEmail(), request.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        // generate access token
        String accessToken = jwtService.generateToken(authentication);

        User user = userRepository.findByUsernameOrEmail(request.getUsernameOrEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // generate refresh token
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId(), ipAddress, userAgent);

        log.info("User logged in successfully: ", user.getEmail());

        AuthResponse loginResponse = AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .username(user.getUsername())
                .email(user.getEmail()).build();

        return loginResponse;
    }
}
