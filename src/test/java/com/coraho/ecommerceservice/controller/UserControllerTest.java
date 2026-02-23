package com.coraho.ecommerceservice.controller;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.coraho.ecommerceservice.DTO.UpdateProfileRequest;
import com.coraho.ecommerceservice.DTO.UpdateUserAddressRequest;
import com.coraho.ecommerceservice.DTO.UserAddressResponse;
import com.coraho.ecommerceservice.DTO.UserProfileResponse;
import com.coraho.ecommerceservice.config.RateLimitConfig;
import com.coraho.ecommerceservice.entity.UserAddress.AddressType;
import com.coraho.ecommerceservice.repository.UserRepository;
import com.coraho.ecommerceservice.security.CustomUserDetailsService;
import com.coraho.ecommerceservice.security.JwtAuthenticationFilter;
import com.coraho.ecommerceservice.security.JwtService;
import com.coraho.ecommerceservice.service.LoginAttemptService;
import com.coraho.ecommerceservice.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;

@WebMvcTest(UserController.class)
@DisplayName("UserController Tests")
public class UserControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private UserService userService;
    @MockitoBean
    private RateLimitConfig rateLimitConfig;
    @MockitoBean
    private JwtAuthenticationFilter jwtAuthenticationFilter;
    @MockitoBean
    private JwtService jwtService;
    @MockitoBean
    private CustomUserDetailsService customUserDetailsService;
    @MockitoBean
    private UserRepository userRepository;
    @MockitoBean
    private LoginAttemptService loginAttemptService;

    private UserProfileResponse profileResponse;
    private UserAddressResponse addressResponse;
    private UpdateProfileRequest updateProfileRequest;
    private UpdateUserAddressRequest updateAddressRequest;

    @BeforeEach
    void setUp() {
        profileResponse = UserProfileResponse.builder()
                .id(1L)
                .email("test@example.com")
                .firstName("John")
                .lastName("Doe")
                .build();

        addressResponse = UserAddressResponse.builder()
                .id(1L)
                .addressLine1("123 Main St")
                .city("Springfield")
                .country("US")
                .isDefault(false)
                .build();

        updateProfileRequest = UpdateProfileRequest.builder()
                .firstName("Jane")
                .lastName("Doe")
                .build();

        updateAddressRequest = UpdateUserAddressRequest.builder()
                .addressType(AddressType.SHIPPING)
                .firstName("Jane")
                .lastName("Doe")
                .addressLine1("456 Elm St")
                .city("Shelbyville")
                .stateProvince("IL")
                .postalCode("62565")
                .country("US")
                .build();
    }

    // -------------------------------------------------------------------------
    // GET /api/user
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("GET /api/user - getCurrentUserProfile")
    class GetCurrentUserProfile {
        @Test
        @WithMockUser
        @DisplayName("returns 200 and profile when authenticated")
        void returnsProfile_whenAuthenticated() throws Exception {
            when(userService.getCurrentUserProfile()).thenReturn(profileResponse);

            mockMvc.perform(get("/api/user"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.email").value("test@example.com"))
                    .andExpect(jsonPath("$.firstName").value("John"));

            verify(userService).getCurrentUserProfile();
        }
    }
}
