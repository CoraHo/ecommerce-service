package com.coraho.ecommerceservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
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
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import com.coraho.ecommerceservice.DTO.UpdateProfileRequest;
import com.coraho.ecommerceservice.DTO.UpdateUserAddressRequest;
import com.coraho.ecommerceservice.DTO.UserAddressResponse;
import com.coraho.ecommerceservice.DTO.UserProfileResponse;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.entity.UserAddress;
import com.coraho.ecommerceservice.entity.UserAddress.AddressType;
import com.coraho.ecommerceservice.exception.DuplicateResourceException;
import com.coraho.ecommerceservice.exception.NoChangesDetectedException;
import com.coraho.ecommerceservice.exception.ResourceNotFoundException;
import com.coraho.ecommerceservice.repository.UserAddressRepository;
import com.coraho.ecommerceservice.repository.UserRepository;

@ExtendWith(MockitoExtension.class)
@DisplayName("UserService Tests")
public class UserServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private EmailVerificationTokenService emailVerificationTokenService;
    @Mock
    private UserAddressRepository userAddressRepository;
    @Mock
    private Authentication authentication;
    @Mock
    private SecurityContext securityContext;

    @InjectMocks
    private UserService userService;

    private User testUser;
    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_USERNAME = "testuser";
    private static final Long TEST_USER_ID = 1L;

    @BeforeEach
    void setUp() {
        testUser = createTestUser();
        mockSecurityContext();
    }

    @AfterEach
    void tearDown() {
        // Clean up SecurityContextHolder after each test
        SecurityContextHolder.clearContext();
    }

    // ===== getCurrentUserProfile Tests =====

    @Test
    @DisplayName("Should get current user profile successfully")
    void shouldGetCurrentUserProfileSuccessfully() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        // When
        UserProfileResponse profile = userService.getCurrentUserProfile();

        // Then
        assertThat(profile).isNotNull();
        assertThat(profile.getId()).isEqualTo(TEST_USER_ID);
        assertThat(profile.getUsername()).isEqualTo(TEST_USERNAME);
        assertThat(profile.getFirstName()).isEqualTo("John");
        assertThat(profile.getLastName()).isEqualTo("Doe");
        verify(userRepository, times(1)).findByEmail(TEST_EMAIL);
    }

    @Test
    @DisplayName("Should throw exception when user is not logged in")
    void shouldThrowExceptionWhenUserNotAuthenticated() {
        // Given
        when(securityContext.getAuthentication()).thenReturn(null);

        // When & Then
        assertThatThrownBy(() -> userService.getCurrentUserProfile())
                .isInstanceOf(InsufficientAuthenticationException.class)
                .hasMessageContaining("User not logged in");
    }

    @Test
    @DisplayName("Should throw exception when authentictaion is not authenticated")
    void shouldThrowExceptionWhenAuthenticationNotAuthenticated() {
        // Given
        when(authentication.isAuthenticated()).thenReturn(false);

        // When & Then
        assertThatThrownBy(() -> userService.getCurrentUserProfile())
                .isInstanceOf(InsufficientAuthenticationException.class)
                .hasMessageContaining("User not logged in");
    }

    // ===== updateUserProfile Tests =====

    @Test
    @DisplayName("Should update user profile successfully with basic info changes")
    void shouldUpdateUserProfileWithBasicInfoChanges() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        UpdateProfileRequest request = UpdateProfileRequest.builder()
                .firstName("Jane")
                .lastName("Smith")
                .phoneNumber("9876543210")
                .email(TEST_EMAIL)
                .username(TEST_USERNAME)
                .build();

        User updatedUser = createTestUser();
        updatedUser.setFirstName("Jane");
        updatedUser.setLastName("Smith");
        updatedUser.setPhoneNumber("9876543210");

        when(userRepository.save(any(User.class))).thenReturn(updatedUser);

        // When
        UserProfileResponse response = userService.updateUserProfile(request);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getFirstName()).isEqualTo("Jane");
        assertThat(response.getLastName()).isEqualTo("Smith");
        assertThat(response.getPhoneNumber()).isEqualTo("9876543210");

        // Verify the actual argument passed into them mocked
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        assertThat(userCaptor.getValue().getUpdatedAt()).isNotNull();
    }

    @Test
    @DisplayName("Should throw NoChangesDetectedException when no changes in profile")
    void shouldThrowNoChangesDetectedExceptionWhenNoChanges() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        UpdateProfileRequest request = UpdateProfileRequest.builder()
                .firstName(testUser.getFirstName())
                .lastName(testUser.getLastName())
                .phoneNumber(testUser.getPhoneNumber())
                .email(testUser.getEmail())
                .username(testUser.getUsername())
                .build();

        // When & Then
        assertThatThrownBy(() -> userService.updateUserProfile(request))
                .isInstanceOf(NoChangesDetectedException.class)
                .hasMessageContaining("No changes in user profile");

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should update username when new username is available")
    void shouldUpdateUsernameWhenAvailable() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        String newUsername = "newusername";
        UpdateProfileRequest request = UpdateProfileRequest.builder()
                .firstName(testUser.getFirstName())
                .lastName(testUser.getLastName())
                .phoneNumber(testUser.getPhoneNumber())
                .email(testUser.getEmail())
                .username(newUsername)
                .build();

        when(userRepository.findByUsername(newUsername)).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        UserProfileResponse response = userService.updateUserProfile(request);

        // Then
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        assertThat(userCaptor.getValue().getUsername()).isEqualTo(newUsername);
    }

    @Test
    @DisplayName("Should throw DuplicateResourceException when username already exists")
    void shouldThrowExceptionWhenUsernameAlreadyExists() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        String existingUsername = "existinguser";
        UpdateProfileRequest request = UpdateProfileRequest.builder()
                .firstName(testUser.getFirstName())
                .lastName(testUser.getLastName())
                .phoneNumber(testUser.getPhoneNumber())
                .email(testUser.getEmail())
                .username(existingUsername)
                .build();

        User existingUser = new User();
        when(userRepository.findByUsername(existingUsername)).thenReturn(Optional.of(existingUser));

        // When & Then
        assertThatThrownBy(() -> userService.updateUserProfile(request))
                .isInstanceOf(DuplicateResourceException.class)
                .hasMessageContaining("Username already exists");

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should update email and trigger verification when new email is available")
    void shouldUpdateEmailAndTriggerVerification() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        String newEmail = "newemail@example.com";
        UpdateProfileRequest request = UpdateProfileRequest.builder()
                .firstName(testUser.getFirstName())
                .lastName(testUser.getLastName())
                .phoneNumber(testUser.getPhoneNumber())
                .email(newEmail)
                .username(testUser.getUsername())
                .build();

        when(userRepository.findByEmail(newEmail)).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        doNothing().when(emailVerificationTokenService).createAndSendEmailVerificationToken(any(User.class));

        // When
        UserProfileResponse response = userService.updateUserProfile(request);

        // Then
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();

        assertThat(savedUser.getEmail()).isEqualTo(newEmail);
        assertThat(savedUser.getIsEmailVerified()).isFalse();
        verify(emailVerificationTokenService, times(1)).createAndSendEmailVerificationToken(savedUser);
    }

    @Test
    @DisplayName("Should throw DuplicateResourceException when email already exists")
    void shouldThrowExceptionWhenEmailAlreadyExists() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        String existingEmail = "existing@example.com";
        UpdateProfileRequest request = UpdateProfileRequest.builder()
                .firstName(testUser.getFirstName())
                .lastName(testUser.getLastName())
                .phoneNumber(testUser.getPhoneNumber())
                .email(existingEmail)
                .username(testUser.getUsername())
                .build();

        User existingUser = new User();
        when(userRepository.findByEmail(existingEmail)).thenReturn(Optional.of(existingUser));

        // When & Then
        assertThatThrownBy(() -> userService.updateUserProfile(request))
                .isInstanceOf(DuplicateResourceException.class)
                .hasMessageContaining("Email already exists");

        verify(userRepository, never()).save(any(User.class));
    }

    // ===== getCurrentUserAddresses Tests =====

    @Test
    @DisplayName("Should get all addresses for current user")
    void shouldGetAllAddressesForCurrentUser() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        List<UserAddress> addresses = createTestAddresses();
        when(userAddressRepository.findByUserId(TEST_USER_ID)).thenReturn(addresses);

        // When
        List<UserAddressResponse> response = userService.getCurrentUserAddresses();

        // Then
        assertThat(response).hasSize(2);
        assertThat(response.get(0).getCity()).isEqualTo("New York");
        assertThat(response.get(1).getCity()).isEqualTo("Los Angeles");
        verify(userAddressRepository, times(1)).findByUserId(TEST_USER_ID);
    }

    @Test
    @DisplayName("Should return empty list when user has no addresses")
    void shouldReturnEmptyListWhenNoAddresses() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));
        when(userAddressRepository.findByUserId(TEST_USER_ID)).thenReturn(new ArrayList<>());

        // When
        List<UserAddressResponse> response = userService.getCurrentUserAddresses();

        // Then
        assertThat(response).isEmpty();
        verify(userAddressRepository, times(1)).findByUserId(TEST_USER_ID);
    }

    // ===== addUserAddress Tests =====

    @Test
    @DisplayName("Should add new user address successfully")
    void shouldAddNewUserAddressSuccessfully() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        UpdateUserAddressRequest request = createAddressRequest(false);
        UserAddress savedAddress = createUserAddress(1L, "New York", false);

        when(userAddressRepository.save(any(UserAddress.class))).thenReturn(savedAddress);

        // When
        UserAddressResponse response = userService.addUserAddress(request);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getCity()).isEqualTo("New York");
        assertThat(response.getIsDefault()).isFalse();

        verify(userAddressRepository, times(1)).save(any(UserAddress.class));
        verify(userAddressRepository, never()).clearDefaultAddresses(anyLong());
    }

    @Test
    @DisplayName("Should clear other default addresses when adding new default address")
    void shouldClearOtherDefaultAddressesWhenAddingDefault() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        UpdateUserAddressRequest request = createAddressRequest(true);
        UserAddress savedAddress = createUserAddress(1L, "New York", true);

        when(userAddressRepository.save(any(UserAddress.class))).thenReturn(savedAddress);
        doNothing().when(userAddressRepository).clearDefaultAddresses(TEST_USER_ID);

        // When
        UserAddressResponse response = userService.addUserAddress(request);

        // Then
        assertThat(response.getIsDefault()).isTrue();
        verify(userAddressRepository, times(1)).clearDefaultAddresses(TEST_USER_ID);
        verify(userAddressRepository, times(1)).save(any(UserAddress.class));
    }

    @Test
    @DisplayName("Should set isDefault to false when not specified in request")
    void shouldSetIsDefaultToFalseWhenNotSpecified() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        UpdateUserAddressRequest request = createAddressRequest(null);
        UserAddress savedAddress = createUserAddress(1L, "New York", false);

        when(userAddressRepository.save(any(UserAddress.class))).thenReturn(savedAddress);

        // When
        UserAddressResponse response = userService.addUserAddress(request);

        // Then
        ArgumentCaptor<UserAddress> addressCaptor = ArgumentCaptor.forClass(UserAddress.class);
        verify(userAddressRepository).save(addressCaptor.capture());
        assertThat(addressCaptor.getValue().getIsDefault()).isFalse();
    }

    // ===== updateUserAddress Tests =====

    @Test
    @DisplayName("Should update user address successfully")
    void shouldUpdateUserAddressSuccessfully() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        Long addressId = 1L;
        UserAddress existingAddress = createUserAddress(addressId, "New York", false);
        UpdateUserAddressRequest request = createAddressRequest(false);
        request.setCity("Boston");

        when(userAddressRepository.findById(addressId)).thenReturn(Optional.of(existingAddress));
        when(userAddressRepository.save(any(UserAddress.class))).thenReturn(existingAddress);

        // When
        UserAddressResponse response = userService.updateUserAddress(addressId, request);

        // Then
        assertThat(response).isNotNull();
        ArgumentCaptor<UserAddress> addressCaptor = ArgumentCaptor.forClass(UserAddress.class);
        verify(userAddressRepository).save(addressCaptor.capture());
        assertThat(addressCaptor.getValue().getCity()).isEqualTo("Boston");
    }

    @Test
    @DisplayName("Should throw ResourceNotFoundException when address not found for update")
    void shouldThrowExceptionWhenAddressNotFoundForUpdate() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        Long addressId = 999L;
        UpdateUserAddressRequest request = createAddressRequest(false);

        when(userAddressRepository.findById(addressId)).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> userService.updateUserAddress(addressId, request))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Address not found");

        verify(userAddressRepository, never()).save(any(UserAddress.class));
    }

    @Test
    @DisplayName("Should clear other defaults when updating address to default")
    void shouldClearOtherDefaultsWhenUpdatingToDefault() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        Long addressId = 1L;
        UserAddress existingAddress = createUserAddress(addressId, "New York", false);
        UpdateUserAddressRequest request = createAddressRequest(true);

        when(userAddressRepository.findById(addressId)).thenReturn(Optional.of(existingAddress));
        when(userAddressRepository.save(any(UserAddress.class))).thenReturn(existingAddress);
        doNothing().when(userAddressRepository).clearDefaultAddresses(TEST_USER_ID);

        // When
        UserAddressResponse response = userService.updateUserAddress(addressId, request);

        // Then
        verify(userAddressRepository, times(1)).clearDefaultAddresses(TEST_USER_ID);
        ArgumentCaptor<UserAddress> addressCaptor = ArgumentCaptor.forClass(UserAddress.class);
        verify(userAddressRepository).save(addressCaptor.capture());
        assertThat(addressCaptor.getValue().getIsDefault()).isTrue();
    }

    // ===== deleteUserAddress Tests =====

    @Test
    @DisplayName("Should delete user address successfully")
    void shouldDeleteUserAddressSuccessfully() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        Long addressId = 1L;
        UserAddress userAddress = createUserAddress(addressId, "New York", false);

        when(userAddressRepository.findByIdAndUserId(addressId, TEST_USER_ID))
                .thenReturn(Optional.of(userAddress));
        doNothing().when(userAddressRepository).delete(userAddress);

        // When
        userService.deleteUserAddress(addressId);

        // Then
        verify(userAddressRepository, times(1)).findByIdAndUserId(addressId, TEST_USER_ID);
        verify(userAddressRepository, times(1)).delete(userAddress);
    }

    @Test
    @DisplayName("Should throw ResourceNotFoundException when address not found for deletion")
    void shouldThrowExceptionWhenAddressNotFoundForDeletion() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        Long addressId = 999L;
        when(userAddressRepository.findByIdAndUserId(addressId, TEST_USER_ID))
                .thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> userService.deleteUserAddress(addressId))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("User Address not found");

        verify(userAddressRepository, never()).delete(any(UserAddress.class));
    }

    // ===== setDefaultUserAddress Tests =====

    @Test
    @DisplayName("Should set address as default successfully")
    void shouldSetAddressAsDefaultSuccessfully() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        Long addressId = 1L;
        UserAddress userAddress = createUserAddress(addressId, "New York", false);

        when(userAddressRepository.findByIdAndUserId(addressId, TEST_USER_ID))
                .thenReturn(Optional.of(userAddress));
        when(userAddressRepository.save(any(UserAddress.class))).thenReturn(userAddress);
        doNothing().when(userAddressRepository).clearDefaultAddresses(TEST_USER_ID);

        // When
        UserAddressResponse response = userService.setDefaultUserAddress(addressId);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getIsDefault()).isTrue();

        verify(userAddressRepository, times(1)).clearDefaultAddresses(TEST_USER_ID);
        ArgumentCaptor<UserAddress> addressCaptor = ArgumentCaptor.forClass(UserAddress.class);
        verify(userAddressRepository).save(addressCaptor.capture());
        assertThat(addressCaptor.getValue().getIsDefault()).isTrue();
    }

    @Test
    @DisplayName("Should throw ResourceNotFoundException when address not found for setting default")
    void shouldThrowExceptionWhenAddressNotFoundForSettingDefault() {
        // Given
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testUser));

        Long addressId = 999L;
        when(userAddressRepository.findByIdAndUserId(addressId, TEST_USER_ID))
                .thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> userService.setDefaultUserAddress(addressId))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("User Address not found");

        verify(userAddressRepository, never()).clearDefaultAddresses(anyLong());
        verify(userAddressRepository, never()).save(any(UserAddress.class));
    }

    // ===== Helper Methods =====

    private User createTestUser() {
        User user = new User();
        user.setId(TEST_USER_ID);
        user.setEmail(TEST_EMAIL);
        user.setUsername(TEST_USERNAME);
        user.setFirstName("John");
        user.setLastName("Doe");
        user.setPhoneNumber("1234567890");
        user.setIsEmailVerified(true);
        user.setIsActive(true);
        user.setIsLocked(false);
        user.setCreatedAt(LocalDateTime.now());
        return user;
    }

    private void mockSecurityContext() {
        lenient().when(authentication.isAuthenticated()).thenReturn(true);
        lenient().when(authentication.getName()).thenReturn(TEST_EMAIL);
        lenient().when(securityContext.getAuthentication()).thenReturn(authentication);
        SecurityContextHolder.setContext(securityContext);
    }

    private List<UserAddress> createTestAddresses() {
        List<UserAddress> addresses = new ArrayList<>();
        addresses.add(createUserAddress(1L, "New York", true));
        addresses.add(createUserAddress(2L, "Los Angeles", false));
        return addresses;
    }

    private UserAddress createUserAddress(Long id, String city, Boolean isDefault) {
        return UserAddress.builder()
                .id(id)
                .user(testUser)
                .addressType(AddressType.BILLING)
                .isDefault(isDefault)
                .firstName("John")
                .lastName("Doe")
                .phoneNumber("1234567890")
                .addressLine1("123 Main St")
                .addressLine2("Apt 4B")
                .city(city)
                .stateProvince("NY")
                .postalCode("10001")
                .country("USA")
                .build();
    }

    private UpdateUserAddressRequest createAddressRequest(Boolean isDefault) {
        return UpdateUserAddressRequest.builder()
                .addressType(AddressType.BILLING)
                .isDefault(isDefault)
                .firstName("John")
                .lastName("Doe")
                .phoneNumber("1234567890")
                .addressLine1("123 Main St")
                .addressLine2("Apt 4B")
                .city("New York")
                .stateProvince("NY")
                .postalCode("10001")
                .country("USA")
                .build();
    }

}
