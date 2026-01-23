package com.coraho.ecommerceservice.controller;

import com.coraho.ecommerceservice.DTO.*;
import com.coraho.ecommerceservice.service.*;
import org.springframework.web.bind.annotation.*;

import com.coraho.ecommerceservice.entity.RefreshToken;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.exception.RefreshTokenException;
import com.coraho.ecommerceservice.security.JwtService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationService authenticationService;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    private final UserService userService;
    private final EmailVerificationTokenService emailVerificationTokenService;
    private final PasswordResetService passwordResetService;
    private final SessionManagementService sessionManagementService;

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

    // This API requires user login
    @PutMapping("/reset-password")
    public ResponseEntity<?> resetPasswordWithCurrentPassword(@RequestBody PasswordResetRequest request,
            HttpSession session) {
        // retrieve user from database
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            ErrorResponse errorResponse = ErrorResponse.builder()
                    .error("Unauthorized")
                    .message("Authentication failed")
                    .status(HttpStatus.UNAUTHORIZED.value())
                    .timestamp(LocalDateTime.now().toString())
                    .path("/api/auth/reset-password")
                    .build();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        }
        String email = authentication.getName();

        passwordResetService.resetPasswordWithCurrentPassword(request, email);

        // invalidate all user sessions except the current one
        sessionManagementService.invalidateAllUserSessionsExceptCurrent(email, session.getId());

        return ResponseEntity.ok("Password has been reset successfully");
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestBody PasswordRequest passwordRequest) {
        passwordResetService.forgotPassword(passwordRequest.getEmail());

        return ResponseEntity.ok("Reset password email is sent successfully");
    }

    @GetMapping("/validate-reset-password-token")
    public ResponseEntity<String> verifyResetPasswordToken(@RequestParam String token) {
        // validate password reset token
        passwordResetService.validatePasswordResetToken(token);

        return ResponseEntity.ok("Password reset token is verified successfully");
    }

    @PostMapping("/reset-password-with-token")
    public ResponseEntity<String> resetPasswordWithToken(ResetPasswordWithTokenRequest request) {
        String email = passwordResetService.resetPasswordWithToken(request);

        // invalidate all user sessions
        sessionManagementService.invalidateAllUserSessions(email);

        return ResponseEntity.ok("Password has been reset successfully");
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
            HttpServletRequest request, HttpSession session) {

        String ipAddress = getCurrentIpAddress(request);
        String userAgent = request.getHeader("User-Agent");

        AuthResponse authResponse = authenticationService.authenticate(loginRequest, ipAddress, userAgent);

        // session is automatically created and stored in database
        session.setAttribute("user", authResponse.getEmail());
        session.setAttribute("loginTime", LocalDateTime.now());

        authResponse.setSessionId(session.getId());

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
    public ResponseEntity<?> logout(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest, HttpSession session) {
        refreshTokenService.revokeToken(refreshTokenRequest.getRefreshToken());
        // session remvoed from database
        session.invalidate();
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

        // invalidae all spring sessions for this user
        sessionManagementService.invalidateAllUserSessions(email);

        return ResponseEntity.status(HttpStatus.OK).body("All sesions logged out seccessfully.");
    }

    @GetMapping("/session-info")
    public ResponseEntity<?> getSessionInfo(HttpSession session) {
        return ResponseEntity.ok(Map.of(
                "sessionId", session.getId(),
                "creationTime", session.getCreationTime(),
                "lastAccessedTime", session.getLastAccessedTime(),
                "maxInactiveInterval", session.getMaxInactiveInterval(),
                "isNew", session.isNew()));
    }

    private String getCurrentIpAddress(HttpServletRequest request) {
        String xForwardFor = request.getHeader("X-Forwarded-For");
        if (xForwardFor != null && !xForwardFor.isEmpty()) {
            return xForwardFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

}
