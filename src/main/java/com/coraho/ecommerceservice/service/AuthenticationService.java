package com.coraho.ecommerceservice.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.coraho.ecommerceservice.DTO.LoginRequest;
import com.coraho.ecommerceservice.DTO.RegisterRequest;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public User signup(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email already exists");
        }
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("Username already exists");
        }

        User user = User.builder()
                .email(request.getEmail())
                .username(request.getUsername())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .build();

        userRepository.save(user);
        return user;
    }

    public User authenticate(LoginRequest request) {
        authenticationManager
                .authenticate(
                        new UsernamePasswordAuthenticationToken(request.getUsernameOrEmail(), request.getPassword()));
        return userRepository.findByUsernameOrEmail(request.getUsernameOrEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User does not exist with the email or username."));
    }
}
