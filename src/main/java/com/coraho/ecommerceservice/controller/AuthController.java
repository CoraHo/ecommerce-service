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
    private final EmailVerificationTokenService emailVerificationTokenService;
    private final PasswordResetService passwordResetService;
    private final SessionManagementService sessionManagementService;

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest registerRequest) {
        RegisterResponse registerUser = authenticationService.signup(registerRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(registerUser);
    }

    @GetMapping("/verify-email")
    public ResponseEntity<String> verifyEmail(@RequestParam String token) {
        emailVerificationTokenService.verifyEmail(token);
        return ResponseEntity.ok("Email verified successfully");
    }

    // user update their password from their profile
    @PutMapping("/reset-password")
    public ResponseEntity<String> resetPasswordWithCurrentPassword(@RequestBody PasswordResetRequest request,
            HttpSession session) {
        passwordResetService.resetPasswordWithCurrentPassword(request);

        // invalidate all user sessions except the current one
        sessionManagementService.invalidateAllUserSessionsExceptCurrent(session.getId());
        return ResponseEntity.ok("Password has been reset successfully");
    }

    // user request forgot password before they login
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

    // user reset their password from forgot password request token
    @PostMapping("/reset-password-with-token")
    public ResponseEntity<String> resetPasswordWithToken(ResetPasswordWithTokenRequest request) {
        String email = passwordResetService.resetPasswordWithToken(request);

        // invalidate all user sessions
        sessionManagementService.invalidateAllUserSessions(email);
        return ResponseEntity.ok("Password has been reset successfully");
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<String> resendVerification() {
        emailVerificationTokenService.resendVerificationEmail();
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
    public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest) {
        // Get the refresh token
        String requestRefreshToken = refreshTokenRequest.getRefreshToken();
        // Generate a new JWT access token based on the refresh token
        AuthResponse response = refreshTokenService.refreshAccessToken(requestRefreshToken);
        return ResponseEntity.ok(response);
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
        refreshTokenService.revokeAllUserTokens();

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
