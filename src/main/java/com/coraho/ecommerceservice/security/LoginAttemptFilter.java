package com.coraho.ecommerceservice.security;

import java.io.IOException;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import com.coraho.ecommerceservice.service.LoginAttemptService;

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
            // TO-DO send blocked response

            return;
        }

        // TO-DO Check if user is locked and the remaning locked time

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
}
