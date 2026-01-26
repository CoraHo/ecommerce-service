package com.coraho.ecommerceservice.security;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureCredentialsExpiredEvent;
import org.springframework.security.authentication.event.AuthenticationFailureDisabledEvent;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.coraho.ecommerceservice.entity.LoginAttempt.AttemptResult;
import com.coraho.ecommerceservice.service.LoginAttemptService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthenticationEventListener {

    private final LoginAttemptService loginAttemptService;

    /* Handle successful authentication - update login attempt */
    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        Authentication authentication = event.getAuthentication();
        String email = extractEmail(authentication);

        if (email == null) {
            log.warn("Could not extract email from authentication");
            return;
        }

        HttpServletRequest request = getCurrenRequest();
        String ipAddress = extractIpAddress(request);
        String userAgent = extractUserAgent(request);

        // record successful login attempt
        loginAttemptService.recordLoginAttempt(email, ipAddress, userAgent, AttemptResult.SUCCESS, null);

        // handle successful login
        loginAttemptService.handleSuccessfullogin(email);

        log.info("Successful authentication for user: {} from IP: {}", email, ipAddress);

    }

    @EventListener
    public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) {
        Authentication authentication = event.getAuthentication();
        String email = extractEmail(authentication);

        HttpServletRequest request = getCurrenRequest();
        String ipAddress = extractIpAddress(request);
        String userAgent = extractUserAgent(request);

        // Check for suspicious activity before record
        if (loginAttemptService.isSuspiciousActivity(email, ipAddress)) {
            loginAttemptService.recordLoginAttempt(email, ipAddress, userAgent, AttemptResult.FAILED,
                    "Suspicious activity detected");
            log.warn("Blocked login attempt due to suspicious activity - email: {}, IP: {}", email, ipAddress);
            return;
        }

        // Record failed login attempt
        loginAttemptService.recordLoginAttempt(email, ipAddress, userAgent, AttemptResult.FAILED,
                "Invalid credentials");

        // Handle failed login
        loginAttemptService.handleFailedLogin(email);

        log.warn("Failed authentictaion for user: {} from IP: {}", email, ipAddress);

    }

    @EventListener
    public void onAuthenticationFailureLocked(AuthenticationFailureLockedEvent event) {
        Authentication authentication = event.getAuthentication();
        String email = extractEmail(authentication);

        HttpServletRequest request = getCurrenRequest();
        String ipAddress = extractIpAddress(request);
        String userAgent = extractUserAgent(request);

        // Record failed login attempt
        loginAttemptService.recordLoginAttempt(email, ipAddress, userAgent, AttemptResult.FAILED, "Account locked");

        log.warn("Login attempt on locked account - email: {}, IP ; {}", email, ipAddress);
    }

    @EventListener
    public void onAuthenticationFailureDisabled(AuthenticationFailureDisabledEvent event) {
        Authentication authentication = event.getAuthentication();
        String email = extractEmail(authentication);

        HttpServletRequest request = getCurrenRequest();
        String ipAddress = extractIpAddress(request);
        String userAgent = extractUserAgent(request);

        // Record failed login attempt
        loginAttemptService.recordLoginAttempt(email, ipAddress, userAgent, AttemptResult.FAILED, "Account disabled");

        log.warn("Login attempt on disabled account - email: {}, IP ; {}", email, ipAddress);
    }

    @EventListener
    public void onAuthenticationFailureCredentialsExpired(AuthenticationFailureCredentialsExpiredEvent event) {
        Authentication authentication = event.getAuthentication();
        String email = extractEmail(authentication);

        HttpServletRequest request = getCurrenRequest();
        String ipAddress = extractIpAddress(request);
        String userAgent = extractUserAgent(request);

        // Record failed login attempt
        loginAttemptService.recordLoginAttempt(email, ipAddress, userAgent, AttemptResult.FAILED,
                "Credentials expired");

        log.warn("Login attempt with expired credentials - email: {}, IP ; {}", email, ipAddress);
    }

    private String extractEmail(Authentication authentication) {
        if (authentication == null)
            return null;

        Object principal = authentication.getPrincipal();

        if (principal instanceof UserDetails) {
            return ((UserDetails) principal).getUsername();
        }

        if (principal instanceof String) {
            return (String) principal;
        }

        return null;
    }

    private HttpServletRequest getCurrenRequest() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

        if (attributes == null) {
            log.warn("Could not get request attributes");
            return null;
        }

        return attributes.getRequest();
    }

    private String extractIpAddress(HttpServletRequest request) {
        if (request == null)
            return "UNKNOWN";

        String[] headerNames = {
                "X-Forwarded-For",
                "X-Real-IP",
                "Proxy-Client-IP",
                "WL-Proxy-Client-IP",
                "HTTP_X_FORWARDED_FOR",
                "HTTP_X_FORWARDED",
                "HTTP_X_CLUSTER_CLIENT_IP",
                "HTTP_CLIENT_IP",
                "HTTP_FORWARDED_FOR",
                "HTTP_FORWARDED",
                "HTTP_VIA",
                "REMOTE_ADDR"
        };

        for (String header : headerNames) {
            String ip = request.getHeader(header);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                // X-Forwarded-For can contain multiple IPs, take the first one
                if (ip.contains(",")) {
                    ip = ip.split(",")[0].trim();
                }
                return ip;
            }
        }
        return request.getRemoteAddr();
    }

    private String extractUserAgent(HttpServletRequest request) {
        if (request == null)
            return "UNKNOWN";

        String userAgent = request.getHeader("User-Agent");
        return userAgent != null ? userAgent : "UNKNOWN";
    }
}
