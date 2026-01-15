package com.coraho.ecommerceservice.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.coraho.ecommerceservice.DTO.LoginRequest;
import com.coraho.ecommerceservice.DTO.RefreshTokenRequest;
import com.coraho.ecommerceservice.DTO.AuthResponse;
import com.coraho.ecommerceservice.DTO.ErrorResponse;
import com.coraho.ecommerceservice.DTO.RegisterRequest;
import com.coraho.ecommerceservice.DTO.RegisterResponse;
import com.coraho.ecommerceservice.entity.RefreshToken;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.exception.RefreshTokenException;
import com.coraho.ecommerceservice.security.JwtService;
import com.coraho.ecommerceservice.service.AuthenticationService;
import com.coraho.ecommerceservice.service.EmailVerificationTokenService;
import com.coraho.ecommerceservice.service.RefreshTokenService;
import com.coraho.ecommerceservice.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import java.time.LocalDateTime;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationService authenticationService;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    private final UserService userService;
    private final EmailVerificationTokenService emailVerificationTokenService;

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest registerRequest) {
        RegisterResponse registerUser = authenticationService.signup(registerRequest);

        return ResponseEntity.status(HttpStatus.CREATED).body(registerUser);
    }

    @GetMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestParam String token) {
        emailVerificationTokenService.verifyEmail(token);

        return ResponseEntity.ok("Email verified successfully");
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<?> resendVerification() {
        // get current Authentication
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            ErrorResponse errorResponse = ErrorResponse.builder()
                    .error("Unauthorized")
                    .message("Authentication failed")
                    .status(HttpStatus.UNAUTHORIZED.value())
                    .timestamp(LocalDateTime.now().toString())
                    .path("/api/auth/logout-all")
                    .build();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        }

        String email = authentication.getName();
        emailVerificationTokenService.resendVerificationEmail(email);

        return ResponseEntity.ok("Verification email sent successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> authenticate(@Valid @RequestBody LoginRequest loginRequest,
            HttpServletRequest request) {
        String ipAddress = getCurrentIpAddress(request);
        String userAgent = request.getHeader("User-Agent");

        AuthResponse authResponse = authenticationService.authenticate(loginRequest, ipAddress, userAgent);

        return ResponseEntity.status(HttpStatus.OK).body(authResponse);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest) {
        String requestRefreshToken = refreshTokenRequest.getRefreshToken();
        // get current Authentication
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            ErrorResponse errorResponse = ErrorResponse.builder()
                    .error("Unauthorized")
                    .message("Authentication failed")
                    .status(HttpStatus.UNAUTHORIZED.value())
                    .timestamp(LocalDateTime.now().toString())
                    .path("/api/auth/logout-all")
                    .build();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        }

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String newAccessToken = jwtService.generateToken(authentication);
                    return ResponseEntity.status(HttpStatus.OK).body(AuthResponse.builder()
                            .accessToken(newAccessToken)
                            .refreshToken(requestRefreshToken)
                            .username(user.getUsername())
                            .email(user.getEmail())
                            .build());
                })
                .orElseThrow(() -> new RefreshTokenException("Refresh token Not found."));

    }

    @PostMapping("/log-out")
    public ResponseEntity<?> logout(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest) {
        refreshTokenService.revokeToken(refreshTokenRequest.getRefreshToken());
        return ResponseEntity.status(HttpStatus.OK).body("Logout successfully.");
    }

    // log out all for the current user
    @PostMapping("/logout-all")
    public ResponseEntity<?> logoutAll() {
        // get current Authentication
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            ErrorResponse errorResponse = ErrorResponse.builder()
                    .error("Unauthorized")
                    .message("Authentication failed")
                    .status(HttpStatus.UNAUTHORIZED.value())
                    .timestamp(LocalDateTime.now().toString())
                    .path("/api/auth/logout-all")
                    .build();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        }

        String email = authentication.getName();
        // get user by email
        User user = userService.findUserByEmail(email);
        // revoke all refresh tokens under the user
        refreshTokenService.revokeAllUserTokens(user.getId());

        return ResponseEntity.status(HttpStatus.OK).body("All sesions logged out seccessfully.");
    }

    private String getCurrentIpAddress(HttpServletRequest request) {
        String xForwardFor = request.getHeader("X-Forwarded-For");
        if (xForwardFor != null && !xForwardFor.isEmpty()) {
            return xForwardFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
