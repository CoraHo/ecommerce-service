package com.coraho.ecommerceservice.security;

import java.io.IOException;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import com.coraho.ecommerceservice.config.RateLimitConfig;
import com.coraho.ecommerceservice.config.RateLimitConfig.RateLimitType;

import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class RateLimitInterceptor implements HandlerInterceptor {

    private final RateLimitConfig rateLimitConfig;

    private final Map<String, RateLimitType> ENDPOINT_LIMITS = Map.of(
            "api/auth/login", RateLimitType.LOGIN,
            "api/auth/forgot-password", RateLimitType.FORGOT_PASSWORD,
            "api/auth/reset-password", RateLimitType.RESET_PASSWORD,
            "api/auth/resend-verification", RateLimitType.RESEND_VERIFICATION,
            "api/auth/register", RateLimitType.REGISTER,
            "api/auth/refresh-token", RateLimitType.REFRESH_TOKEN);

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws IOException {

        String path = request.getRequestURI();
        RateLimitType rateLimitType = ENDPOINT_LIMITS.get(path);

        if (rateLimitType == null) {
            return true;
        }

        String key = buildRateLimitKey(request, path);
        Bucket bucket = rateLimitConfig.resolveBucket(key, rateLimitType);
        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);

        // when one token is consumed successfully from the bucket, continue hanlding
        // the endpoint
        if (probe.isConsumed()) {
            response.setHeader("X-Rate-Limit-Remaining", String.valueOf(probe.getRemainingTokens()));
            return true;
        }

        // when rate limit exceeded
        long waitForRefill = probe.getNanosToWaitForRefill() / 1_000_000_000;

        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setHeader("X-Rate-Limit-Retry-After-Seconds", String.valueOf(waitForRefill));
        response.setContentType("application.json");
        response.getWriter().write(String.format(
                "{\\\"error\\\":\\\"Too many requests\\\",\\\"message\\\":\\\"Rate limit exceeded. Try again in %d seconds\\\",\\\"retryAfter\\\":%d}",
                waitForRefill, waitForRefill));

        log.warn("Rate limit exceeded for {} on endpoint {}", key, path);
        return false;
    }

    private String buildRateLimitKey(HttpServletRequest request, String endpoint) {
        // get client IP address
        String ip = getClientIP(request);
        return ip + ":" + endpoint;
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }

}
