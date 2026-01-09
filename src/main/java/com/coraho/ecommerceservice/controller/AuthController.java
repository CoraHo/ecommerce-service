package com.coraho.ecommerceservice.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.coraho.ecommerceservice.DTO.LoginRequest;
import com.coraho.ecommerceservice.DTO.LoginResponse;
import com.coraho.ecommerceservice.DTO.RegisterRequest;
import com.coraho.ecommerceservice.DTO.RegisterResponse;
import com.coraho.ecommerceservice.service.AuthenticationService;
import com.coraho.ecommerceservice.service.JwtService;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationService authenticationService;
    private final JwtService jwtService;

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@RequestBody RegisterRequest registerRequest) {
        RegisterResponse registerUser = authenticationService.signup(registerRequest);

        return ResponseEntity.status(HttpStatus.CREATED).body(registerUser);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> authenticate(@RequestBody LoginRequest loginRequest) {
        Authentication authentictaion = authenticationService.authenticate(loginRequest);
        String jwtToken = jwtService.generateToken(authentictaion);

        return ResponseEntity.status(HttpStatus.OK).body(new LoginResponse(jwtToken));
    }

}
