package com.coraho.ecommerceservice.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtAuthenticationFilter Tests")
public class JwtAuthenticationFilterTest {

    @Mock
    JwtService jwtService;
    @Mock
    CustomUserDetailsService customUserDetailsService;
    @Mock
    FilterChain filterChain;
    @Mock
    HttpServletRequest request;
    @Mock
    HttpServletResponse response;

    @InjectMocks
    JwtAuthenticationFilter jwtAuthenticationFilter;

    private UserDetails mockUserDetails;
    private static final String VALID_TOKEN = "valid.jwt.token";
    private static final String VALID_EMAIL = "john@example.com";
    private static final String BEARER_VALID_TOKEN = "Bearer " + VALID_TOKEN;

    @BeforeEach
    void setup() {
        mockUserDetails = User.builder()
                .username(VALID_EMAIL)
                .password("")
                .authorities(List.of(new SimpleGrantedAuthority("ROLE_USER")))
                .build();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Nested
    class WhenTokenIsValid {

        @BeforeEach
        void setUp() {
            when(request.getHeader("Authorization")).thenReturn(BEARER_VALID_TOKEN);
            when(jwtService.isTokenValid(VALID_TOKEN)).thenReturn(true);
            when(jwtService.getUsernameFromToken(VALID_TOKEN)).thenReturn(VALID_EMAIL);
            when(customUserDetailsService.loadUserByUsername(VALID_EMAIL)).thenReturn(mockUserDetails);
        }

        @Test
        void shouldPopulateSecurityContext() throws Exception {
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            assertEquals(VALID_EMAIL, authentication.getName());
        }

        @Test
        void shouldSetCorrectAuthoritiesInContext() throws Exception {
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            assertThat(authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_USER")));
        }

        @Test
        void shouldMarkAuthenticationAsAuthenticated() throws Exception {
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            assertTrue(SecurityContextHolder.getContext().getAuthentication().isAuthenticated());
        }

        @Test
        void shouldAlwaysContinueFilterChain() throws Exception {
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
        }
    }

    @Nested
    class WhenTokenIsInvalid {

        @BeforeEach
        void setUp() {
            when(request.getHeader("Authorization")).thenReturn(BEARER_VALID_TOKEN);
            when(jwtService.isTokenValid(BEARER_VALID_TOKEN)).thenReturn(false);
        }

        @Test
        void shouldNotPopulateSecurityContext() throws Exception {
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            assertNull(SecurityContextHolder.getContext().getAuthentication());
        }

        @Test
        void shouldNotCallUserDetailsService() throws Exception {
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verifyNoInteractions(customUserDetailsService);
        }

        @Test
        void shouldAlwaysContinueFilterChain() throws Exception {
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
        }
    }

    @Nested
    class WhenAuthorizationHeaderIsMissing {

        @BeforeEach
        void setUp() {
            when(request.getHeader("Authorization")).thenReturn(null);
        }

        @Test
        void shouldNotPopulateSecurityContext() throws Exception {
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            assertNull(SecurityContextHolder.getContext().getAuthentication());
        }

        @Test
        void shouldNotInteractWithJwtService() throws Exception {
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verifyNoInteractions(jwtService);
        }

        @Test
        void shouldAlwaysContinueFilterChain() throws Exception {
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
        }
    }

    @Nested
    class WhenAuthorizationHeaderIsMalformed {

        @Test
        void whenNoBearerPrefix_shouldNotPopulateSecurityContext() throws Exception {
            when(request.getHeader("Authorization")).thenReturn("Basic sometoken");

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            assertNull(SecurityContextHolder.getContext().getAuthentication());
            verifyNoInteractions(jwtService);
        }

        @Test
        void whenBearerOnly_shouldNotPopulateSecurityContext() throws Exception {
            when(request.getHeader("Authorization")).thenReturn("Bearer ");

            // "Bearer " with nothing after → substring(7) = "" which is not null
            // so jwtService.isTokenValid("") will be called — return false
            when(jwtService.isTokenValid("")).thenReturn(false);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            assertNull(SecurityContextHolder.getContext().getAuthentication());
        }

        @Test
        void shouldAlwaysContinueFilterChain() throws Exception {
            when(request.getHeader("Authorization")).thenReturn("Basic sometoken");

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
        }
    }

    @Nested
    class WhenExceptionIsThrown {

        @Test
        void whenJwtServiceThrows_shouldNotPopulateSecurityContext() throws Exception {
            when(request.getHeader("Authorization")).thenReturn(BEARER_VALID_TOKEN);
            when(jwtService.isTokenValid(VALID_TOKEN))
                    .thenThrow(new RuntimeException("Token parsing failed"));

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            assertNull(SecurityContextHolder.getContext().getAuthentication());
        }

        @Test
        void whenUserDetailsServiceThrows_shouldNotPopulateSecurityContext() throws Exception {
            when(request.getHeader("Authorization")).thenReturn(BEARER_VALID_TOKEN);
            when(jwtService.isTokenValid(VALID_TOKEN)).thenReturn(true);
            when(jwtService.getUsernameFromToken(VALID_TOKEN)).thenReturn(VALID_EMAIL);
            when(customUserDetailsService.loadUserByUsername(VALID_EMAIL))
                    .thenThrow(new RuntimeException("User not found"));

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            assertNull(SecurityContextHolder.getContext().getAuthentication());
        }

        @Test
        void whenExceptionIsThrown_shouldAlwaysContinueFilterChain() throws Exception {
            // Critical: a broken filter must NEVER halt the chain
            when(request.getHeader("Authorization")).thenReturn(BEARER_VALID_TOKEN);
            when(jwtService.isTokenValid(VALID_TOKEN))
                    .thenThrow(new RuntimeException("Unexpected failure"));

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
        }
    }

}
