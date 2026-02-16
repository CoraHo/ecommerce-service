package com.coraho.ecommerceservice.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.coraho.ecommerceservice.repository.UserRepository;
import com.coraho.ecommerceservice.service.AuthenticationService;
import com.coraho.ecommerceservice.service.EmailVerificationTokenService;
import com.coraho.ecommerceservice.service.RefreshTokenService;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthenticationService Test")
public class AuthenticationServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private JwtService jwtService;
    @Mock
    private RefreshTokenService refreshTokenService;
    @Mock
    private EmailVerificationTokenService emailVerificationTokenService;
    @Mock
    private SecurityContext securityContext;
    @Mock
    private Authentication authentication;

    @InjectMocks
    private AuthenticationService authenticationService;

    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_USERNAME = "testuser";
    private static final String TEST_PASSWORD = "Password123!";
    private static final String ENCODED_PASSWORD = "$2a$10$encodedPassword";
    private static final String TEST_FIRST_NAME = "John";
    private static final String TEST_LAST_NAME = "Doe";
    private static final Long TEST_USER_ID = 1L;
    private static final String TEST_ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
    private static final String TEST_REFRESH_TOKEN = "refresh-token-uuid";
    private static final String TEST_IP_ADDRESS = "192.168.1.1";
    private static final String TEST_USER_AGENT = "Mozilla/5.0";

    @BeforeEach
    void setUp() {
        SecurityContextHolder.setContext(securityContext);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }
}
