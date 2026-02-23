package com.coraho.ecommerceservice.controller;

import org.springframework.web.bind.annotation.RestController;

import com.coraho.ecommerceservice.DTO.UpdateProfileRequest;
import com.coraho.ecommerceservice.DTO.UpdateUserAddressRequest;
import com.coraho.ecommerceservice.DTO.UserAddressResponse;
import com.coraho.ecommerceservice.DTO.UserProfileResponse;
import com.coraho.ecommerceservice.service.UserService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PathVariable;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping()
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserProfileResponse> getCurrentUserProfile() {
        UserProfileResponse profile = userService.getCurrentUserProfile();
        return ResponseEntity.ok(profile);
    }

    @PutMapping()
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserProfileResponse> updateUserProfile(
            @Valid @RequestBody UpdateProfileRequest updateProfileRequest) {

        UserProfileResponse userProfileResponse = userService.updateUserProfile(updateProfileRequest);

        return ResponseEntity.ok(userProfileResponse);
    }

    @GetMapping("/addresses")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<UserAddressResponse>> getUserAddresses() {
        List<UserAddressResponse> addresses = userService.getCurrentUserAddresses();
        return ResponseEntity.ok(addresses);
    }

    @PostMapping("/addresses")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserAddressResponse> addUserAddress(@Valid @RequestBody UpdateUserAddressRequest request) {
        UserAddressResponse response = userService.addUserAddress(request);
        return ResponseEntity.ok(response);
    }

    @PutMapping("addresses/{addressId}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserAddressResponse> updateUserAddress(@PathVariable Long addressId,
            @RequestBody UpdateUserAddressRequest request) {
        UserAddressResponse userAddress = userService.updateUserAddress(addressId, request);
        return ResponseEntity.ok(userAddress);
    }

    @DeleteMapping("addreses/{addressId}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<String> deleteAddress(@PathVariable Long addressId) {
        userService.deleteUserAddress(addressId);
        return ResponseEntity.ok("Address " + addressId + " deleted.");
    }

    @PatchMapping("addresses/{addressId}/set-default")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserAddressResponse> setDefaultAddress(@PathVariable Long addressId) {
        UserAddressResponse userAddress = userService.setDefaultUserAddress(addressId);
        return ResponseEntity.ok(userAddress);
    }

}
