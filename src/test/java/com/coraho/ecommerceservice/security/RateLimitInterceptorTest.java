package com.coraho.ecommerceservice.security;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.when;

import java.io.StringWriter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.coraho.ecommerceservice.config.RateLimitConfig;
import com.coraho.ecommerceservice.config.RateLimitConfig.RateLimitType;

import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@ExtendWith(MockitoExtension.class)
@DisplayName("RateLimitInterceptor tests")
public class RateLimitInterceptorTest {

    @Mock
    private RateLimitConfig rateLimitConfig;
    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    @Mock
    private Object handler;
    @Mock
    private Bucket bucket;
    @Mock
    private ConsumptionProbe probe;

    @InjectMocks
    private RateLimitInterceptor rateLimitInterceptor;

    private StringWriter responseWriter;

    @BeforeEach
    void setUp() {
        responseWriter = new StringWriter();
    }

    // Helper
    private void mockIp(String ip) {
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn(ip);
    }

    private void mockBucketFor(String uri, String ip) {
        when(rateLimitConfig.resolveBucket(eq(ip + ":" + uri), any(RateLimitType.class))).thenReturn(bucket);
        when(bucket.tryConsumeAndReturnRemaining(1)).thenReturn(probe);
    }

    @Nested
    class WhenEndpointIsNotRateLimited {

        @Test
        void shouldReturnTrue() throws Exception {
            when(request.getRequestURI()).thenReturn("/api/auth/profile");

            boolean result = rateLimitInterceptor.preHandle(request, response, handler);

            assertTrue(result);
        }
    }
}
