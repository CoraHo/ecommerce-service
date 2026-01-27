package com.coraho.ecommerceservice.security;

import java.io.IOException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import com.coraho.ecommerceservice.service.LoginAttemptService;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class LoginAttemptFilter extends OncePerRequestFilter {

    private final LoginAttemptService loginAttemptService;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Check for login request
        if (!isLoginRequest(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Check if IP is blocked
        String ipAddress = extractIpAddress(request);
        if (loginAttemptService.isIpBlocked(ipAddress)) {
            log.warn("Blocked request from IP address: {}", ipAddress);
            // Send blocked response
            sendBlockedResponse(response, "Too many failed attempts from this IP address. Please try again later.",
                    null);
            return;
        }

        // TO-DO Check if user is locked and the remaning locked time
        String email = extractEmailFromRequest(request);

        if (email != null && loginAttemptService.isUserLocked(email)) {
            Optional<Duration> lockoutRemaining = loginAttemptService.getLockoutRemaining(email);
            String message = "Account is temporarily locked due to multiple failed login attempts.";
            sendBlockedResponse(response, message, lockoutRemaining.orElse(null));
            return;
        }

        filterChain.doFilter(request, response);
    }

    /* Check if this is a login request */
    private boolean isLoginRequest(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        String method = request.getMethod();

        return "POST".equalsIgnoreCase(method) && (requestURI.contains("/login") ||
                requestURI.contains("/auth/login") ||
                requestURI.contains("/api/auth/login"));
    }

    /* Extract IP address handling proxies and load balancers */
    private String extractIpAddress(HttpServletRequest request) {
        String[] headerNames = {
                "X-Forwarded-For",
                "X-Real-IP",
                "Proxy-Client-IP",
                "WL-Proxy-Client-IP"
        };

        for (String header : headerNames) {
            String ip = request.getHeader(header);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                if (ip.contains(",")) {
                    ip = ip.split(",")[0].trim();
                }
                return ip;
            }
        }

        return request.getRemoteAddr();
    }

    /* Send blocked response with appropriate status and message */
    private void sendBlockedResponse(HttpServletResponse response, String message, Duration lockoutRemaining)
            throws IOException {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> errorResponse = new HashMap<>();

        errorResponse.put("error", "Too many requests");
        errorResponse.put("message", message);
        errorResponse.put("Status", HttpStatus.TOO_MANY_REQUESTS.value());

        if (lockoutRemaining != null) {
            errorResponse.put("retryAfterSeconds", lockoutRemaining.getSeconds());
            errorResponse.put("retryAfterMunites", lockoutRemaining.toMinutes());
            response.setHeader("Retry-After", String.valueOf(lockoutRemaining.getSeconds()));
        }

        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }

    /* Extract email from request */
    private String extractEmailFromRequest(HttpServletRequest request) throws IOException {
        /**
         * This is tricky because reading the request consumes it
         * In a real implementation, we need to use a wrapper to cache the body or
         * extract from a specific header
         * 
         * For now, we'll skip this and rely on the event listener
         * which has access to the authentication object
         */
        return null;
    }
}
