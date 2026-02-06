package com.coraho.ecommerceservice.service;

import com.coraho.ecommerceservice.DTO.UpdateProfileRequest;
import com.coraho.ecommerceservice.DTO.UpdateUserAddressRequest;
import com.coraho.ecommerceservice.DTO.UserAddressResponse;
import com.coraho.ecommerceservice.DTO.UserProfileResponse;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.entity.UserAddress;
import com.coraho.ecommerceservice.exception.DuplicateResourceException;
import com.coraho.ecommerceservice.exception.NoChangesDetectedException;
import com.coraho.ecommerceservice.exception.ResourceNotFoundException;
import com.coraho.ecommerceservice.repository.UserAddressRepository;
import com.coraho.ecommerceservice.repository.UserRepository;

import lombok.RequiredArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final EmailVerificationTokenService emailVerificationTokenService;
    private final UserAddressRepository userAddressRepository;

    public User findUserByEmail(String email) {
        return userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    public User findUserByUsername(String username) {
        User user = userRepository.findByUsername(username).orElseThrow(
                () -> new UsernameNotFoundException("User not found by username: " + username));

        return user;
    }

    public UserProfileResponse getCurrentUserProfile() {
        User user = getCurrentAuthenticatedUser();
        return mapToUserProfileResponse(user);
    }

    /**
     * Update the user information in User entity
     * 
     * @param request
     * @return A instance of UserProfileResponse
     */
    @Transactional
    public UserProfileResponse updateUserProfile(UpdateProfileRequest request) {
        User user = getCurrentAuthenticatedUser();

        // check if user information updated or not
        if (user.getFirstName().equals(request.getFirstName())
                && user.getLastName().equals(request.getLastName())
                && user.getPhoneNumber().equals(request.getPhoneNumber())
                && user.getEmail().equals(request.getEmail())
                && user.getUsername().equals(request.getUsername())) {
            throw new NoChangesDetectedException("No changes in user profile");
        }

        // update user information
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setPhoneNumber(request.getPhoneNumber());

        // check if the username already exists, when user wants to udpate the username
        if (request.getUsername() != null && !user.getUsername().equals(request.getUsername())) {
            Optional<User> existingUserOpt = userRepository.findByUsername(request.getUsername());
            if (existingUserOpt.isPresent()) {
                throw new DuplicateResourceException("Username already exists");
            } else {
                user.setUsername(request.getUsername());
            }
        }

        // check if the email already exists, when user wants to update the email
        if (request.getEmail() != null && !user.getEmail().equals(request.getEmail())) {
            Optional<User> existingUserOpt = userRepository.findByEmail(request.getEmail());
            if (existingUserOpt.isPresent()) {
                throw new DuplicateResourceException("Email already exists");
            } else {
                user.setEmail(request.getEmail());
                // set isEmailVerified as false and send a email verifictaion email
                user.setIsEmailVerified(false);
                emailVerificationTokenService.createAndSendEmailVerificationToken(user);
            }
        }

        // update the updatedAt time
        user.setUpdatedAt(LocalDateTime.now());
        User updatedUser = userRepository.save(user);

        return mapToUserProfileResponse(updatedUser);
    }

    /**
     * Get all addresses for current user
     * 
     * @return A list of UserAddressResponse instances
     */
    @Transactional(readOnly = true)
    public List<UserAddressResponse> getCurrentUserAddresses() {
        User user = getCurrentAuthenticatedUser();

        List<UserAddress> addresses = userAddressRepository.findByUserId(user.getId());

        List<UserAddressResponse> addressResponses = addresses.stream()
                .map(this::mapToUserAddressResponse)
                .collect(Collectors.toList());

        return addressResponses;
    }

    /**
     * Add a new UserAddress instance into database
     * 
     * @param request
     * @return A UserAddressResponse instance
     */
    @Transactional
    public UserAddressResponse addUserAddress(UpdateUserAddressRequest request) {
        User user = getCurrentAuthenticatedUser();

        // If this is set as default, clear other default addresses
        if (Boolean.TRUE.equals(request.getIsDefault())) {
            userAddressRepository.clearDefaultAddresses(user.getId());
        }

        UserAddress address = UserAddress.builder()
                .user(user)
                .addressType(request.getAddressType())
                .isDefault(request.getIsDefault() != null ? request.getIsDefault() : false)
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .phoneNumber(request.getPhoneNumber())
                .addressLine1(request.getAddressLine1())
                .addressLine2(request.getAddressLine2())
                .city(request.getCity())
                .stateProvince(request.getStateProvince())
                .postalCode(request.getPostalCode())
                .country(request.getCountry())
                .build();

        UserAddress savedAddress = userAddressRepository.save(address);

        // TODO: log the change in AuditLog

        return mapToUserAddressResponse(savedAddress);
    }

    /**
     * Update user address in UserAddress table
     * 
     * @param addressId
     * @param request
     * @return
     */
    @Transactional
    public UserAddressResponse updateUserAddress(Long addressId, UpdateUserAddressRequest request) {
        User user = getCurrentAuthenticatedUser();

        UserAddress address = userAddressRepository.findById(addressId)
                .orElseThrow(() -> new ResourceNotFoundException("Address not found"));

        // if the current address is set as default, clear other default addresses
        if (Boolean.TRUE.equals(request.getIsDefault())) {
            userAddressRepository.clearDefaultAddresses(user.getId());
        }

        // Update address fields
        address.setAddressType(request.getAddressType());
        address.setIsDefault(request.getIsDefault() != null ? request.getIsDefault() : false);
        address.setFirstName(request.getFirstName());
        address.setLastName(request.getLastName());
        address.setPhoneNumber(request.getPhoneNumber());
        address.setAddressLine1(request.getAddressLine1());
        address.setAddressLine2(request.getAddressLine2());
        address.setCity(request.getCity());
        address.setStateProvince(request.getStateProvince());
        address.setPostalCode(request.getPostalCode());
        address.setCountry(request.getCountry());

        UserAddress savedAddress = userAddressRepository.save(address);

        // TODO: log the change in AuditLog

        return mapToUserAddressResponse(savedAddress);
    }

    /**
     * Delete the UserAddress by id for the current logged-in user
     * 
     * @param userAddressId
     */
    public void deleteUserAddress(Long userAddressId) {
        User user = getCurrentAuthenticatedUser();

        UserAddress userAddress = userAddressRepository.findByIdAndUserId(userAddressId, user.getId())
                .orElseThrow(() -> new ResourceNotFoundException("User Address not found"));

        userAddressRepository.delete(userAddress);

        // TODO: log the change in AuditLog
    }

    /**
     * Update the default user address
     * 
     * @param userAddressId
     * @return
     */
    public UserAddressResponse setDefaultUserAddress(Long userAddressId) {
        User user = getCurrentAuthenticatedUser();

        UserAddress userAddress = userAddressRepository.findByIdAndUserId(userAddressId, user.getId())
                .orElseThrow(() -> new ResourceNotFoundException("User Address not found"));

        // Clear all default addresses first
        userAddressRepository.clearDefaultAddresses(user.getId());

        // Set this address as default
        userAddress.setIsDefault(true);

        UserAddress savedUserAddress = userAddressRepository.save(userAddress);

        // TODO: log this change in AuditLog

        return mapToUserAddressResponse(savedUserAddress);
    }

    // helper methods

    private User getCurrentAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new InsufficientAuthenticationException("User not logged in");
        }
        String email = authentication.getName();
        User currentUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return currentUser;
    }

    private UserProfileResponse mapToUserProfileResponse(User user) {
        List<UserAddressResponse> addresses = user.getUserAddresses().stream()
                .map(this::mapToUserAddressResponse)
                .collect(Collectors.toList());

        return UserProfileResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .phoneNumber(user.getPhoneNumber())
                .isEmailVerified(user.getIsEmailVerified())
                .lastLoginAt(user.getLastLoginAt())
                .createdAt(user.getCreatedAt())
                .addresses(addresses)
                .build();

    }

    private UserAddressResponse mapToUserAddressResponse(UserAddress userAddress) {
        return UserAddressResponse.builder()
                .id(userAddress.getId())
                .addressType(userAddress.getAddressType())
                .isDefault(userAddress.getIsDefault())
                .firstName(userAddress.getFirstName())
                .lastName(userAddress.getLastName())
                .phoneNumber(userAddress.getPhoneNumber())
                .addressLine1(userAddress.getAddressLine1())
                .addressLine2(userAddress.getAddressLine2())
                .city(userAddress.getCity())
                .stateProvince(userAddress.getStateProvince())
                .postalCode(userAddress.getPostalCode())
                .country(userAddress.getCountry())
                .build();
    }

}
