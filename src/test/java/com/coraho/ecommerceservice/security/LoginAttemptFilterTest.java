package com.coraho.ecommerceservice.security;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import com.coraho.ecommerceservice.service.LoginAttemptService;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@ExtendWith(MockitoExtension.class)
@DisplayName("LoginAttemptFilter Tests")
public class LoginAttemptFilterTest {

    @Mock
    private LoginAttemptService loginAttemptService;
    @Mock
    private FilterChain filterChain;
    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;

    @InjectMocks
    private LoginAttemptFilter loginAttemptFilter;

    private StringWriter responseWriter;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        responseWriter = new StringWriter();
        loginAttemptFilter = new LoginAttemptFilter(loginAttemptService, objectMapper);
    }

    // Helper: configure request as a valid login request
    private void mockLoginRequest() {
        when(request.getMethod()).thenReturn("POST");
        when(request.getRequestURI()).thenReturn("api/auth/login");
    }

    // Helper: configure response writer capture
    private void mockResponseWriter() throws Exception {
        when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));
    }

    @Nested
    class WhenRequestIdNotALoginRequest {

        @Test
        void whenGetMethod_shouldPassThrough() throws Exception {
            when(request.getMethod()).thenReturn("GET");
            when(request.getRequestURI()).thenReturn("api/auth/login");

            loginAttemptFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verifyNoInteractions(loginAttemptService);
        }

        @Test
        void whenDifferentUri_shouldPassThrough() throws Exception {
            when(request.getMethod()).thenReturn("POST");
            when(request.getRequestURI()).thenReturn("api/auth/profile");

            loginAttemptFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verifyNoInteractions(loginAttemptService);
        }

        @Test
        void whenPutMethod_shouldPassThrough() throws Exception {
            when(request.getMethod()).thenReturn("PUT");
            when(request.getRequestURI()).thenReturn("api/auth/login");

            loginAttemptFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verifyNoInteractions(loginAttemptService);
        }

        @Test
        void whenMethodIsCaseInsensitivePost_shouldTreatAsLoginRequest() throws Exception {
            // "POST".equalsIgnoreCase covers "post", "Post" etc.
            when(request.getMethod()).thenReturn("post");
            when(request.getRequestURI()).thenReturn("api/auth/login");
            when(request.getRemoteAddr()).thenReturn("192.168.1.1");
            when(loginAttemptService.isIpBlocked("192.168.1.1")).thenReturn(false);

            loginAttemptFilter.doFilterInternal(request, response, filterChain);

            // Verified as a login request — loginAttemptService was consulted
            verify(loginAttemptService).isIpBlocked("192.168.1.1");
        }
    }

    @Nested
    class WhenIpIsBlocked {

        @BeforeEach
        void setUp() throws Exception {
            mockLoginRequest();
            mockResponseWriter();
            when(request.getRemoteAddr()).thenReturn("10.0.0.1");
            when(loginAttemptService.isIpBlocked("10.0.0.1")).thenReturn(true);
        }

        @Test
        void shouldNotContinueFilterChain() throws Exception {
            loginAttemptFilter.doFilterInternal(request, response, filterChain);

            verifyNoInteractions(filterChain);
        }

        @Test
        void shouldReturn429Status() throws Exception {
            loginAttemptFilter.doFilterInternal(request, response, filterChain);

            verify(response).setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        }

        @Test
        void shouldReturnJsonContentType() throws Exception {
            loginAttemptFilter.doFilterInternal(request, response, filterChain);

            verify(response).setContentType(MediaType.APPLICATION_JSON_VALUE);
        }

        @Test
        void shouldIncludeErrorAndMessageInBody() throws Exception {
            loginAttemptFilter.doFilterInternal(request, response, filterChain);

            String body = responseWriter.toString();
            assertTrue(body.contains("Too many requests"));
            assertTrue(body.contains("Too many failed attempts from this IP address"));
        }

        @Test
        void shouldNotCheckUserLockout() throws Exception {
            loginAttemptFilter.doFilterInternal(request, response, filterChain);

            // IP blocked — should short-circuit before ever checking user lockout
            verify(loginAttemptService, never()).isUserLocked(anyString());
        }
    }

    @Nested
    class WhenIpIsNotBlocked {

        @BeforeEach
        void setUp() throws Exception {
            mockLoginRequest();
            when(request.getRemoteAddr()).thenReturn("10.0.0.1");
            when(loginAttemptService.isIpBlocked("10.0.0.1")).thenReturn(false);
        }

        @Test
        void whenEmailIsNull_shouldContinueFilterChain() throws Exception {
            loginAttemptFilter.doFilter(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verify(loginAttemptService, never()).isUserLocked(anyString());
        }
    }
}
