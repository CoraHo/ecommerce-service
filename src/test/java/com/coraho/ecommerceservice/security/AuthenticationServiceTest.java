package com.coraho.ecommerceservice.security;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.LocalDateTime;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.coraho.ecommerceservice.DTO.AuthResponse;
import com.coraho.ecommerceservice.DTO.LoginRequest;
import com.coraho.ecommerceservice.DTO.RegisterRequest;
import com.coraho.ecommerceservice.DTO.RegisterResponse;
import com.coraho.ecommerceservice.entity.RefreshToken;
import com.coraho.ecommerceservice.entity.User;
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

        private User activeUser;

        @BeforeEach
        void setUp() {
                SecurityContextHolder.setContext(securityContext);
                activeUser = createSavedUser();
        }

        @AfterEach
        void tearDown() {
                SecurityContextHolder.clearContext();
        }

        // ===== signup Tests =====

        @Test
        @DisplayName("Should register new user successfully")
        void shouldRegisterNewUserSuccessfully() {
                // Given
                RegisterRequest request = createRegisterRequest();

                when(userRepository.existsByEmail(TEST_EMAIL)).thenReturn(false);
                when(userRepository.existsByUsername(TEST_USERNAME)).thenReturn(false);
                when(passwordEncoder.encode(TEST_PASSWORD)).thenReturn(ENCODED_PASSWORD);
                when(userRepository.save(any(User.class))).thenReturn(activeUser);
                doNothing().when(emailVerificationTokenService).createAndSendEmailVerificationToken(any(User.class));

                // When
                RegisterResponse response = authenticationService.signup(request);

                // Then
                assertThat(response).isNotNull();
                assertThat(response.getId()).isEqualTo(TEST_USER_ID);
                assertThat(response.getEmail()).isEqualTo(TEST_EMAIL);
                assertThat(response.getUsername()).isEqualTo(TEST_USERNAME);
                assertThat(response.getFirstName()).isEqualTo(TEST_FIRST_NAME);
                assertThat(response.getLastName()).isEqualTo(TEST_LAST_NAME);
                assertThat(response.isActive()).isTrue();
                assertThat(response.isEmailVerified()).isFalse();
                assertThat(response.isLocked()).isFalse();
                assertThat(response.getCreatedAt()).isNotNull();

                verify(userRepository, times(1)).existsByEmail(TEST_EMAIL);
                verify(userRepository, times(1)).existsByUsername(TEST_USERNAME);
                verify(passwordEncoder, times(1)).encode(TEST_PASSWORD);
                verify(userRepository, times(1)).save(any(User.class));
                verify(emailVerificationTokenService, times(1)).createAndSendEmailVerificationToken(activeUser);
        }

        @Test
        @DisplayName("Should encode password when creating new user")
        void shouldEncodePasswordWhenCreatingNewUser() {
                // Given
                RegisterRequest request = createRegisterRequest();

                when(userRepository.existsByEmail(TEST_EMAIL)).thenReturn(false);
                when(userRepository.existsByUsername(TEST_USERNAME)).thenReturn(false);
                when(passwordEncoder.encode(TEST_PASSWORD)).thenReturn(ENCODED_PASSWORD);
                when(userRepository.save(any(User.class))).thenReturn(activeUser);
                doNothing().when(emailVerificationTokenService).createAndSendEmailVerificationToken(any(User.class));

                // When
                authenticationService.signup(request);

                // Then
                ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
                verify(userRepository).save(userCaptor.capture());
                User capturedUser = userCaptor.getValue();

                assertThat(capturedUser.getPasswordHash()).isEqualTo(ENCODED_PASSWORD);
                assertThat(capturedUser.getPasswordHash()).isNotEqualTo(TEST_PASSWORD);
                verify(passwordEncoder, times(1)).encode(TEST_PASSWORD);
        }

        @Test
        @DisplayName("Should send email verification token after user registration")
        void shouldSendEmailVerificationTokenAfterRegistration() {
                // Given
                RegisterRequest request = createRegisterRequest();

                when(userRepository.existsByEmail(TEST_EMAIL)).thenReturn(false);
                when(userRepository.existsByUsername(TEST_USERNAME)).thenReturn(false);
                when(passwordEncoder.encode(TEST_PASSWORD)).thenReturn(ENCODED_PASSWORD);
                when(userRepository.save(any(User.class))).thenReturn(activeUser);
                doNothing().when(emailVerificationTokenService).createAndSendEmailVerificationToken(any(User.class));

                // When
                authenticationService.signup(request);

                // Then
                verify(emailVerificationTokenService, times(1)).createAndSendEmailVerificationToken(activeUser);
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when email already exists")
        void shouldThrowExceptionWhenEmailAlreadyExists() {
                // Given
                RegisterRequest request = createRegisterRequest();
                when(userRepository.existsByEmail(TEST_EMAIL)).thenReturn(true);

                // When & Then
                assertThatThrownBy(() -> authenticationService.signup(request))
                                .isInstanceOf(IllegalArgumentException.class)
                                .hasMessageContaining("Email already exists");

                verify(userRepository, times(1)).existsByEmail(TEST_EMAIL);
                verify(userRepository, never()).existsByUsername(anyString());
                verify(userRepository, never()).save(any(User.class));
                verify(emailVerificationTokenService, never()).createAndSendEmailVerificationToken(any(User.class));
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when username already exists")
        void shouldThrowExceptionWhenUsernameAlreadyExists() {
                // Given
                RegisterRequest request = createRegisterRequest();
                when(userRepository.existsByEmail(TEST_EMAIL)).thenReturn(false);
                when(userRepository.existsByUsername(TEST_USERNAME)).thenReturn(true);

                // When & Then
                assertThatThrownBy(() -> authenticationService.signup(request))
                                .isInstanceOf(IllegalArgumentException.class)
                                .hasMessageContaining("Username already exists");

                verify(userRepository, times(1)).existsByEmail(TEST_EMAIL);
                verify(userRepository, times(1)).existsByUsername(TEST_USERNAME);
                verify(userRepository, never()).save(any(User.class));
                verify(emailVerificationTokenService, never()).createAndSendEmailVerificationToken(any(User.class));
        }

        @Test
        @DisplayName("Should check email existence before username")
        void shouldCheckEmailBeforeUsername() {
                // Given
                RegisterRequest request = createRegisterRequest();
                when(userRepository.existsByEmail(TEST_EMAIL)).thenReturn(true);

                // When & Then
                assertThatThrownBy(() -> authenticationService.signup(request))
                                .isInstanceOf(IllegalArgumentException.class);

                // Email check happens first
                verify(userRepository, times(1)).existsByEmail(TEST_EMAIL);
                // Username check should not happen
                verify(userRepository, never()).existsByUsername(anyString());
        }

        @Test
        @DisplayName("Should save user with all required fields")
        void shouldSaveUserWithAllRequiredFields() {
                // Given
                RegisterRequest request = createRegisterRequest();

                when(userRepository.existsByEmail(TEST_EMAIL)).thenReturn(false);
                when(userRepository.existsByUsername(TEST_USERNAME)).thenReturn(false);
                when(passwordEncoder.encode(TEST_PASSWORD)).thenReturn(ENCODED_PASSWORD);
                when(userRepository.save(any(User.class))).thenReturn(activeUser);
                doNothing().when(emailVerificationTokenService).createAndSendEmailVerificationToken(any(User.class));

                // When
                authenticationService.signup(request);

                // Then
                ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
                verify(userRepository).save(userCaptor.capture());
                User capturedUser = userCaptor.getValue();

                assertThat(capturedUser.getEmail()).isEqualTo(TEST_EMAIL);
                assertThat(capturedUser.getUsername()).isEqualTo(TEST_USERNAME);
                assertThat(capturedUser.getPasswordHash()).isEqualTo(ENCODED_PASSWORD);
                assertThat(capturedUser.getFirstName()).isEqualTo(TEST_FIRST_NAME);
                assertThat(capturedUser.getLastName()).isEqualTo(TEST_LAST_NAME);
        }

        // ===== authenticate Tests =====

        @Test
        @DisplayName("Should authenticate user successfully with username")
        void shouldAuthenticateUserSuccessfullyWithUsername() {
                // Given
                LoginRequest request = LoginRequest.builder()
                                .usernameOrEmail(TEST_USERNAME)
                                .password(TEST_PASSWORD)
                                .build();

                RefreshToken refreshToken = createRefreshToken();

                new UsernamePasswordAuthenticationToken(TEST_USERNAME, TEST_PASSWORD);

                when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                                .thenReturn(authentication);
                doNothing().when(securityContext).setAuthentication(authentication);
                when(jwtService.generateToken(authentication)).thenReturn(TEST_ACCESS_TOKEN);
                when(userRepository.findByUsernameOrEmail(TEST_USERNAME)).thenReturn(Optional.of(activeUser));
                when(refreshTokenService.createRefreshToken(TEST_USER_ID, TEST_IP_ADDRESS, TEST_USER_AGENT))
                                .thenReturn(refreshToken);

                // When
                AuthResponse response = authenticationService.authenticate(request, TEST_IP_ADDRESS, TEST_USER_AGENT);

                // Then
                assertThat(response).isNotNull();
                assertThat(response.getAccessToken()).isEqualTo(TEST_ACCESS_TOKEN);
                assertThat(response.getRefreshToken()).isEqualTo(TEST_REFRESH_TOKEN);
                assertThat(response.getUsername()).isEqualTo(TEST_USERNAME);
                assertThat(response.getEmail()).isEqualTo(TEST_EMAIL);

                verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
                verify(securityContext, times(1)).setAuthentication(authentication);
                verify(jwtService, times(1)).generateToken(authentication);
                verify(refreshTokenService, times(1)).createRefreshToken(TEST_USER_ID, TEST_IP_ADDRESS,
                                TEST_USER_AGENT);
        }

        @Test
        @DisplayName("Should authenticate user successfully with email")
        void shouldAuthenticateUserSuccessfullyWithEmail() {
                // Given
                LoginRequest request = LoginRequest.builder()
                                .usernameOrEmail(TEST_EMAIL)
                                .password(TEST_PASSWORD)
                                .build();

                RefreshToken refreshToken = createRefreshToken();

                when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                                .thenReturn(authentication);
                doNothing().when(securityContext).setAuthentication(authentication);
                when(jwtService.generateToken(authentication)).thenReturn(TEST_ACCESS_TOKEN);
                when(userRepository.findByUsernameOrEmail(TEST_EMAIL)).thenReturn(Optional.of(activeUser));
                when(refreshTokenService.createRefreshToken(TEST_USER_ID, TEST_IP_ADDRESS, TEST_USER_AGENT))
                                .thenReturn(refreshToken);

                // When
                AuthResponse response = authenticationService.authenticate(request, TEST_IP_ADDRESS, TEST_USER_AGENT);

                // Then
                assertThat(response).isNotNull();
                assertThat(response.getAccessToken()).isEqualTo(TEST_ACCESS_TOKEN);
                assertThat(response.getRefreshToken()).isEqualTo(TEST_REFRESH_TOKEN);
                verify(userRepository, times(1)).findByUsernameOrEmail(TEST_EMAIL);
        }

        @Test
        @DisplayName("Should set authentication in SecurityContext after successful authentication")
        void shouldSetAuthenticationInSecurityContext() {
                // Given
                LoginRequest request = createLoginRequest();
                RefreshToken refreshToken = createRefreshToken();

                when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                                .thenReturn(authentication);
                doNothing().when(securityContext).setAuthentication(authentication);
                when(jwtService.generateToken(authentication)).thenReturn(TEST_ACCESS_TOKEN);
                when(userRepository.findByUsernameOrEmail(TEST_USERNAME)).thenReturn(Optional.of(activeUser));
                when(refreshTokenService.createRefreshToken(TEST_USER_ID, TEST_IP_ADDRESS, TEST_USER_AGENT))
                                .thenReturn(refreshToken);

                // When
                authenticationService.authenticate(request, TEST_IP_ADDRESS, TEST_USER_AGENT);

                // Then
                verify(securityContext, times(1)).setAuthentication(authentication);
        }

        @Test
        @DisplayName("Should generate JWT access token after authentication")
        void shouldGenerateJwtAccessTokenAfterAuthentication() {
                // Given
                LoginRequest request = createLoginRequest();
                RefreshToken refreshToken = createRefreshToken();

                when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                                .thenReturn(authentication);
                doNothing().when(securityContext).setAuthentication(authentication);
                when(jwtService.generateToken(authentication)).thenReturn(TEST_ACCESS_TOKEN);
                when(userRepository.findByUsernameOrEmail(TEST_USERNAME)).thenReturn(Optional.of(activeUser));
                when(refreshTokenService.createRefreshToken(TEST_USER_ID, TEST_IP_ADDRESS, TEST_USER_AGENT))
                                .thenReturn(refreshToken);

                // When
                AuthResponse response = authenticationService.authenticate(request, TEST_IP_ADDRESS, TEST_USER_AGENT);

                // Then
                assertThat(response.getAccessToken()).isEqualTo(TEST_ACCESS_TOKEN);
                verify(jwtService, times(1)).generateToken(authentication);
        }

        @Test
        @DisplayName("Should create refresh token with user ID, IP address, and user agent")
        void shouldCreateRefreshTokenWithUserIdAndMetadata() {
                // Given
                LoginRequest request = createLoginRequest();
                RefreshToken refreshToken = createRefreshToken();

                when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                                .thenReturn(authentication);
                doNothing().when(securityContext).setAuthentication(authentication);
                when(jwtService.generateToken(authentication)).thenReturn(TEST_ACCESS_TOKEN);
                when(userRepository.findByUsernameOrEmail(TEST_USERNAME)).thenReturn(Optional.of(activeUser));
                when(refreshTokenService.createRefreshToken(TEST_USER_ID, TEST_IP_ADDRESS, TEST_USER_AGENT))
                                .thenReturn(refreshToken);

                // When
                AuthResponse response = authenticationService.authenticate(request, TEST_IP_ADDRESS, TEST_USER_AGENT);

                // Then
                assertThat(response.getRefreshToken()).isEqualTo(TEST_REFRESH_TOKEN);
                verify(refreshTokenService, times(1)).createRefreshToken(TEST_USER_ID, TEST_IP_ADDRESS,
                                TEST_USER_AGENT);
        }

        @Test
        @DisplayName("Should throw BadCredentialsException when authentication fails")
        void shouldThrowBadCredentialsExceptionWhenAuthenticationFails() {
                // Given
                LoginRequest request = LoginRequest.builder()
                                .usernameOrEmail(TEST_USERNAME)
                                .password("wrongPassword")
                                .build();

                when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                                .thenThrow(new BadCredentialsException("Invalid credentials"));

                // When & Then
                assertThatThrownBy(() -> authenticationService.authenticate(request, TEST_IP_ADDRESS, TEST_USER_AGENT))
                                .isInstanceOf(BadCredentialsException.class)
                                .hasMessageContaining("Invalid credentials");

                verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
                verify(securityContext, never()).setAuthentication(any(Authentication.class));
                verify(jwtService, never()).generateToken(any(Authentication.class));
                verify(refreshTokenService, never()).createRefreshToken(anyLong(), anyString(), anyString());
        }

        @Test
        @DisplayName("Should throw UsernameNotFoundException when user not found after authentication")
        void shouldThrowUsernameNotFoundExceptionWhenUserNotFound() {
                // Given
                LoginRequest request = createLoginRequest();

                when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                                .thenReturn(authentication);
                doNothing().when(securityContext).setAuthentication(authentication);
                when(jwtService.generateToken(authentication)).thenReturn(TEST_ACCESS_TOKEN);
                when(userRepository.findByUsernameOrEmail(TEST_USERNAME)).thenReturn(Optional.empty());

                // When & Then
                assertThatThrownBy(() -> authenticationService.authenticate(request, TEST_IP_ADDRESS, TEST_USER_AGENT))
                                .isInstanceOf(UsernameNotFoundException.class)
                                .hasMessageContaining("User not found");

                verify(userRepository, times(1)).findByUsernameOrEmail(TEST_USERNAME);
                verify(refreshTokenService, never()).createRefreshToken(anyLong(), anyString(), anyString());
        }

        @Test
        @DisplayName("Should pass correct credentials to AuthenticationManager")
        void shouldPassCorrectCredentialsToAuthenticationManager() {
                // Given
                LoginRequest request = createLoginRequest();
                RefreshToken refreshToken = createRefreshToken();

                when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                                .thenReturn(authentication);
                doNothing().when(securityContext).setAuthentication(authentication);
                when(jwtService.generateToken(authentication)).thenReturn(TEST_ACCESS_TOKEN);
                when(userRepository.findByUsernameOrEmail(TEST_USERNAME)).thenReturn(Optional.of(activeUser));
                when(refreshTokenService.createRefreshToken(TEST_USER_ID, TEST_IP_ADDRESS, TEST_USER_AGENT))
                                .thenReturn(refreshToken);

                // When
                authenticationService.authenticate(request, TEST_IP_ADDRESS, TEST_USER_AGENT);

                // Then
                ArgumentCaptor<UsernamePasswordAuthenticationToken> authTokenCaptor = ArgumentCaptor
                                .forClass(UsernamePasswordAuthenticationToken.class);
                verify(authenticationManager).authenticate(authTokenCaptor.capture());

                UsernamePasswordAuthenticationToken capturedToken = authTokenCaptor.getValue();
                assertThat(capturedToken.getPrincipal()).isEqualTo(TEST_USERNAME);
                assertThat(capturedToken.getCredentials()).isEqualTo(TEST_PASSWORD);
        }

        @Test
        @DisplayName("Should return AuthResponse with all required fields")
        void shouldReturnAuthResponseWithAllRequiredFields() {
                // Given
                LoginRequest request = createLoginRequest();
                RefreshToken refreshToken = createRefreshToken();

                when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                                .thenReturn(authentication);
                doNothing().when(securityContext).setAuthentication(authentication);
                when(jwtService.generateToken(authentication)).thenReturn(TEST_ACCESS_TOKEN);
                when(userRepository.findByUsernameOrEmail(TEST_USERNAME)).thenReturn(Optional.of(activeUser));
                when(refreshTokenService.createRefreshToken(TEST_USER_ID, TEST_IP_ADDRESS, TEST_USER_AGENT))
                                .thenReturn(refreshToken);

                // When
                AuthResponse response = authenticationService.authenticate(request, TEST_IP_ADDRESS, TEST_USER_AGENT);

                // Then
                assertThat(response.getAccessToken()).isNotNull().isNotEmpty();
                assertThat(response.getRefreshToken()).isNotNull().isNotEmpty();
                assertThat(response.getUsername()).isNotNull().isNotEmpty();
                assertThat(response.getEmail()).isNotNull().isNotEmpty();
        }

        // ===== Helper Methods =====

        private RegisterRequest createRegisterRequest() {
                return RegisterRequest.builder()
                                .email(TEST_EMAIL)
                                .username(TEST_USERNAME)
                                .password(TEST_PASSWORD)
                                .firstName(TEST_FIRST_NAME)
                                .lastName(TEST_LAST_NAME)
                                .build();
        }

        private LoginRequest createLoginRequest() {
                return LoginRequest.builder()
                                .usernameOrEmail(TEST_USERNAME)
                                .password(TEST_PASSWORD)
                                .build();
        }

        private User createSavedUser() {
                User user = new User();
                user.setId(TEST_USER_ID);
                user.setEmail(TEST_EMAIL);
                user.setUsername(TEST_USERNAME);
                user.setPasswordHash(ENCODED_PASSWORD);
                user.setFirstName(TEST_FIRST_NAME);
                user.setLastName(TEST_LAST_NAME);
                user.setIsActive(true);
                user.setIsEmailVerified(false);
                user.setIsLocked(false);
                user.setCreatedAt(LocalDateTime.now());
                return user;
        }

        private RefreshToken createRefreshToken() {
                RefreshToken refreshToken = new RefreshToken();
                refreshToken.setToken(TEST_REFRESH_TOKEN);
                refreshToken.setUser(activeUser);
                refreshToken.setIpAddress(TEST_IP_ADDRESS);
                refreshToken.setUserAgent(TEST_USER_AGENT);
                refreshToken.setExpiresAt(LocalDateTime.now().plusDays(7));
                return refreshToken;
        }
}
