package com.coraho.ecommerceservice.security;

import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.repository.UserRepository;
import jakarta.transaction.Transactional;

import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional // prevent the error from lazy loading of collections
    public UserDetails loadUserByUsername(String usernameOrEmail)
            throws UsernameNotFoundException, DisabledException, LockedException {
        // allow login with both username and email
        User user = userRepository.findByUsernameOrEmailWithRolesAndPermissions(usernameOrEmail).orElseThrow(
                () -> new UsernameNotFoundException("User not found by username or email: " + usernameOrEmail));

        if (!user.getIsActive()) {
            throw new DisabledException("User account is inactive");
        }

        if (user.getIsLocked()) {
            throw new LockedException("User account is locked");
        }

        return new org.springframework.security.core.userdetails.User(
                user.getEmail(), // use email as the principal (consistent identifier)
                user.getPasswordHash(),
                user.getIsActive(),
                true,
                true,
                !user.getIsLocked(),
                getAuthorities(user));
    }

    private Collection<? extends GrantedAuthority> getAuthorities(User user) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        user.getUserRoles().forEach(userRole -> {
            authorities.add(new SimpleGrantedAuthority(userRole.getRole().getName()));

            userRole.getRole().getRolePermissions().forEach(rolePermission -> {
                authorities.add(new SimpleGrantedAuthority(rolePermission.getPermission().getName()));
            });
        });
        return authorities;
    }
}
