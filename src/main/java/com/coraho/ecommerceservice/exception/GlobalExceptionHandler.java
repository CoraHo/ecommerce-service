package com.coraho.ecommerceservice.exception;

import java.time.LocalDateTime;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import com.coraho.ecommerceservice.DTO.ErrorResponse;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<?> handleIllegalArgumentException(IllegalArgumentException e, WebRequest request) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .error("Bad Request")
                .message(e.getMessage())
                .status(HttpStatus.BAD_REQUEST.value())
                .timestamp(LocalDateTime.now().toString())
                .path(extractPath(request))
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<?> handleBadCredentialsException(BadCredentialsException e, WebRequest request) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .error("Unauthorized")
                .message("Invalid username or password") // Don't reveal the actual error
                .status(HttpStatus.UNAUTHORIZED.value())
                .timestamp(LocalDateTime.now().toString())
                .path(extractPath(request))
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
    }

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<ErrorResponse> handleDisabledException(
            DisabledException ex, WebRequest request) {

        ErrorResponse errorResponse = ErrorResponse.builder()
                .error("Forbidden")
                .message("Account is disabled")
                .status(HttpStatus.FORBIDDEN.value())
                .timestamp(LocalDateTime.now().toString())
                .path(extractPath(request))
                .build();

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
    }

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<ErrorResponse> handleLockedException(
            LockedException ex, WebRequest request) {

        ErrorResponse errorResponse = ErrorResponse.builder()
                .error("Forbidden")
                .message("Account is locked")
                .status(HttpStatus.FORBIDDEN.value())
                .timestamp(LocalDateTime.now().toString())
                .path(extractPath(request))
                .build();

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthenticationException(
            AuthenticationException ex, WebRequest request) {

        ErrorResponse errorResponse = ErrorResponse.builder()
                .error("Unauthorized")
                .message("Authentication failed")
                .status(HttpStatus.UNAUTHORIZED.value())
                .timestamp(LocalDateTime.now().toString())
                .path(extractPath(request))
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
    }

    @ExceptionHandler(RefreshTokenException.class)
    public ResponseEntity<?> handleRefreshTokenException(RefreshTokenException e, WebRequest request) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .error("Refresh Token Error")
                .message(e.getMessage())
                .status(HttpStatus.BAD_REQUEST.value())
                .timestamp(LocalDateTime.now().toString())
                .path(extractPath(request))
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleGlobalException(Exception e, WebRequest request) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .error("Internal Server error")
                .message(e.getMessage())
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .timestamp(LocalDateTime.now().toString())
                .path(extractPath(request))
                .build();

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
    }

    private String extractPath(WebRequest request) {
        String description = request.getDescription(false);
        if (description != null & description.startsWith("uri=")) {
            return description.substring(4);
        }
        return description != null ? description : "Unknown";
    }
}
