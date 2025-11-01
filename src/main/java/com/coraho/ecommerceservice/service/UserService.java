package com.coraho.ecommerceservice.service;

import com.coraho.ecommerceservice.entity.Group;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.repository.GroupRepository;
import com.coraho.ecommerceservice.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }


    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    public User findUserByUsername(String username) {
        User user = userRepository.findByUsername(username).orElseThrow(
                () -> new UsernameNotFoundException("User not found by username: " + username)
        );

        return user;
    }

    public void checkUserExistence(String username) {
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("This username already existed: " + username);
        }
    }

    @Transactional
    public User registerUser(String username, String password) {
        if (username.isEmpty() || password.isEmpty()) {
            throw new IllegalArgumentException("Username and Password are required");
        }
        checkUserExistence(username);

        /* create a User object with username and encode password, then add user to database */
        User user = User.builder().username(username)
                .password(passwordEncoder.encode(password))
                .enabled(true).build();

        return userRepository.save(user);
    }

    @Transactional
    public User updateUser(User user) {
        return userRepository.save(user);
    }
}
