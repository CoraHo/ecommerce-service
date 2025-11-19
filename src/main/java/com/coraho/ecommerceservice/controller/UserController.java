package com.coraho.ecommerceservice.controller;

import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService){
        this.userService = userService;
    }

    @GetMapping
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok(userService.findAllUsers());
    }

    @PostMapping
    @PreAuthorize("hasAuthority('ADMIN_PRIVILEGE')")
    public ResponseEntity<User> createUser(@RequestBody User user) {
        User newUser =  userService.registerUser(user.getUsername(), user.getPassword());
        return ResponseEntity.status(HttpStatus.CREATED).body(newUser);
    }

}
