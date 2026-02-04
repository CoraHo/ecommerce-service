package com.coraho.ecommerceservice.service;

import com.coraho.ecommerceservice.DTO.UpdateProfileRequest;
import com.coraho.ecommerceservice.DTO.UserAddressResponse;
import com.coraho.ecommerceservice.DTO.UserProfileResponse;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.entity.UserAddress;
import com.coraho.ecommerceservice.exception.UserProfileException;
import com.coraho.ecommerceservice.repository.UserRepository;

import jakarta.transaction.Transactional;
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

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final EmailVerificationTokenService emailVerificationTokenService;

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

    @Transactional
    public UserProfileResponse updateUserProfile(UpdateProfileRequest request) {
        User user = getCurrentAuthenticatedUser();

        // check if user information updated or not
        if (user.getFirstName().equals(request.getFirstName())
                && user.getLastName().equals(request.getLastName())
                && user.getPhoneNumber().equals(request.getPhoneNumber())
                && user.getEmail().equals(request.getEmail())
                && user.getUsername().equals(request.getUsername())) {
            throw new UserProfileException("No changes in user profile");
        }

        // update user information
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setPhoneNumber(request.getPhoneNumber());

        // check if the username already exists, when user wants to udpate the username
        if (request.getUsername() != null && !user.getUsername().equals(request.getUsername())) {
            Optional<User> existingUserOpt = userRepository.findByUsername(request.getUsername());
            if (existingUserOpt.isPresent()) {
                throw new UserProfileException("Username already exists");
            } else {
                user.setUsername(request.getUsername());
            }
        }

        // check if the email already exists, when user wants to update the email
        if (request.getEmail() != null && !user.getEmail().equals(request.getEmail())) {
            Optional<User> existingUserOpt = userRepository.findByEmail(request.getEmail());
            if (existingUserOpt.isPresent()) {
                throw new UserProfileException("Email already exists");
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
