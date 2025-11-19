package com.coraho.ecommerceservice.service;

import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    public CustomUserDetailsService (UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    @Override
    @Transactional // prevent the error from lazy loading of collections
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(
                () -> new UsernameNotFoundException("User not found by username: " + username));

        List<SimpleGrantedAuthority> authorities = user.getGroups().stream()
                .flatMap(group -> group.getAuthorities().stream())
                .map(authority -> new SimpleGrantedAuthority(authority.getName()))
                .toList();

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.isEnabled(),
                true, true, true,
                authorities
        );
    }
}
