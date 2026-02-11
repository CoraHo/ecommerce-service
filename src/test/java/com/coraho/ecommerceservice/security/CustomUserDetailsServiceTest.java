package com.coraho.ecommerceservice.security;

import java.util.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.coraho.ecommerceservice.entity.Permission;
import com.coraho.ecommerceservice.entity.Role;
import com.coraho.ecommerceservice.entity.RolePermission;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.entity.UserRole;
import com.coraho.ecommerceservice.repository.UserRepository;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(MockitoExtension.class)
@DisplayName("CustomUserDetailsService Tests")
public class CustomUserDetailsServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private CustomUserDetailsService customUserDetailsService;

    private User activeUser;
    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_USERNAME = "testuser";
    private static final String TEST_PASSWORD_HASH = "$2a$10$hashedPassword";

    @BeforeEach
    void setUp() {
        activeUser = createActiveUserWithRolesAndPermissions();
    }

    @Test
    @DisplayName("Should load user by username successfully")
    void shouldLoadUserByUsernameWhenUserExists() {
        // Given
        // Stub the return value of active user when find by username
        when(userRepository.findByUsernameOrEmailWithRolesAndPermissions(TEST_USERNAME))
                .thenReturn(Optional.of(activeUser));

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(TEST_USERNAME);

        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getUsername()).isEqualTo(TEST_EMAIL);
        assertThat(userDetails.getPassword()).isEqualTo(TEST_PASSWORD_HASH);
        assertThat(userDetails.isEnabled()).isTrue();
        assertThat(userDetails.isAccountNonLocked()).isTrue();
        assertThat(userDetails.isAccountNonExpired()).isTrue();
        assertThat(userDetails.isCredentialsNonExpired()).isTrue();

        verify(userRepository, times(1))
                .findByUsernameOrEmailWithRolesAndPermissions(TEST_USERNAME);
    }

    @Test
    @DisplayName("Should load user by email successfully")
    void shouldLoadUserByEmailWhenUserExists() {
        // Given
        // stub the return value of active user when find by email
        when(userRepository.findByUsernameOrEmailWithRolesAndPermissions(TEST_EMAIL))
                .thenReturn(Optional.of(activeUser));

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(TEST_EMAIL);

        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getUsername()).isEqualTo(TEST_EMAIL);

        verify(userRepository, times(1))
                .findByUsernameOrEmailWithRolesAndPermissions(TEST_EMAIL);
    }

    @Test
    @DisplayName("Should throw UsernameNotFoundException when user does not exist")
    void shouldThrowUsernameNotFoundExceptionWhenUserDoesNotExist() {
        // Given
        String nonExistingUser = "nonexistent@example.com";
        when(userRepository.findByUsernameOrEmailWithRolesAndPermissions(nonExistingUser))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> customUserDetailsService.loadUserByUsername(nonExistingUser))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("User not found by username or email: " + nonExistingUser);

        verify(userRepository, times(1))
                .findByUsernameOrEmailWithRolesAndPermissions(nonExistingUser);
    }

    @Test
    @DisplayName("Should throw DisabledException when user is inactive")
    void shouldThrowDisabledExceptionWhenUserIsInactive() {
        User inactiveUser = createActiveUserWithRolesAndPermissions();
        inactiveUser.setIsActive(false);

        when(userRepository.findByUsernameOrEmailWithRolesAndPermissions(TEST_USERNAME))
                .thenReturn(Optional.of(inactiveUser));

        assertThatThrownBy(() -> customUserDetailsService.loadUserByUsername(TEST_USERNAME))
                .isInstanceOf(DisabledException.class)
                .hasMessageContaining("User account is inactive");

        verify(userRepository, times(1))
                .findByUsernameOrEmailWithRolesAndPermissions(TEST_USERNAME);
    }

    @Test
    @DisplayName("Should throw LockedException when user is locked")
    void shouldThrowLockedExceptionWhenUserIsLocked() {
        // Given
        User lockedUser = createActiveUserWithRolesAndPermissions();
        lockedUser.setIsLocked(true);

        when(userRepository.findByUsernameOrEmailWithRolesAndPermissions(TEST_USERNAME))
                .thenReturn(Optional.of(lockedUser));

        // When & Then
        assertThatThrownBy(() -> customUserDetailsService.loadUserByUsername(TEST_USERNAME))
                .isInstanceOf(LockedException.class)
                .hasMessageContaining("User account is locked");

        verify(userRepository, times(1))
                .findByUsernameOrEmailWithRolesAndPermissions(TEST_USERNAME);
    }

    @Test
    @DisplayName("Should handle null username gracefully")
    void shouldHandleNullUsernameGracefully() {
        // Given
        when(userRepository.findByUsernameOrEmailWithRolesAndPermissions(null))
                .thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> customUserDetailsService.loadUserByUsername(null))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    @DisplayName("Should handle empty username gracefully")
    void shouldHandleEmptyUsernameGracefully() {
        // Given
        when(userRepository.findByUsernameOrEmailWithRolesAndPermissions(""))
                .thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> customUserDetailsService.loadUserByUsername(""))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    @DisplayName("Should map user roles to granted authorities correctly")
    void shouldMapUserRolesToGrantedAuthorities() {
        when(userRepository.findByUsernameOrEmailWithRolesAndPermissions(TEST_USERNAME))
                .thenReturn(Optional.of(activeUser));

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(TEST_USERNAME);

        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();

        assertThat(authorities).isNotEmpty();
        assertThat((Collection<GrantedAuthority>) authorities).contains(new SimpleGrantedAuthority("ROLE_USER"));
        assertThat((Collection<GrantedAuthority>) authorities).contains(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    @Test
    @DisplayName("Should map role permissions to granted authorities correctly")
    void shouldMapRolePermissionsToGrantedAuthorities() {
        // Given
        when(userRepository.findByUsernameOrEmailWithRolesAndPermissions(TEST_USERNAME))
                .thenReturn(Optional.of(activeUser));

        // When
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(TEST_USERNAME);

        // Then
        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();

        assertThat((Collection<GrantedAuthority>) authorities).contains(new SimpleGrantedAuthority("product:read"));
        assertThat((Collection<GrantedAuthority>) authorities).contains(new SimpleGrantedAuthority("product:write"));
        assertThat((Collection<GrantedAuthority>) authorities).contains(new SimpleGrantedAuthority("product:delete"));
    }

    @Test
    @DisplayName("Should handle user with multiple roles and permissions")
    void shouldHandleUserWithMultipleRolesAndPermissions() {
        // Given
        when(userRepository.findByUsernameOrEmailWithRolesAndPermissions(TEST_USERNAME))
                .thenReturn(Optional.of(activeUser));

        // When
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(TEST_USERNAME);

        // Then
        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();

        // Should have 2 roles + 3 permissions = 5 total authorities
        assertThat(authorities).hasSize(5);
        assertThat(authorities).extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder(
                        "ROLE_USER",
                        "ROLE_ADMIN",
                        "product:read",
                        "product:write",
                        "product:delete");
    }

    @Test
    @DisplayName("Should handle user with no roles gracefully")
    void shouldHandleUserWithNoRoles() {
        User userWithNoRoles = createUserWithoutRoles();
        when(userRepository.findByUsernameOrEmailWithRolesAndPermissions(TEST_USERNAME))
                .thenReturn(Optional.of(userWithNoRoles));

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(TEST_USERNAME);

        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getAuthorities()).isEmpty();
    }

    @Test
    @DisplayName("Should use email as username in UserDetails")
    void shouldUseEmailAsUsernameInUserDetails() {
        // Given
        when(userRepository.findByUsernameOrEmailWithRolesAndPermissions(TEST_USERNAME))
                .thenReturn(Optional.of(activeUser));

        // When
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(TEST_USERNAME);

        // Then
        assertThat(userDetails.getUsername()).isEqualTo(TEST_EMAIL);
        assertThat(userDetails.getUsername()).isNotEqualTo(TEST_USERNAME);
    }

    // Helper methods to create test data
    private User createActiveUserWithRolesAndPermissions() {
        User user = new User();
        user.setEmail(TEST_EMAIL);
        user.setUsername(TEST_USERNAME);
        user.setPasswordHash(TEST_PASSWORD_HASH);
        user.setIsActive(true);
        user.setIsLocked(false);

        // Create roles with permissions
        Set<UserRole> userRoles = new HashSet<>();

        // ROLE_USER with product read permission
        Role userRole = new Role();
        userRole.setName("ROLE_USER");
        userRole.setDescription("Regular user with basic view previleges");

        Permission readPermission = new Permission();
        readPermission.setName("product:read");
        readPermission.setResource("product");
        readPermission.setAction("read");
        readPermission.setDescription("view products");

        RolePermission rolePermission1 = RolePermission.builder().permission(readPermission).build();
        userRole.setRolePermissions(Set.of(rolePermission1));

        UserRole userRoleMapping1 = UserRole.builder().role(userRole).build();
        userRoles.add(userRoleMapping1);

        // ROLE_ADMIN with product write and read permissions
        Role adminRole = Role.builder().name("ROLE_ADMIN").description("Admin user with all write and read previleges")
                .build();

        Permission writPermission = Permission.builder().name("product:write").resource("product")
                .action("write").description("write products").build();
        Permission deletePermission = Permission.builder().name("product:delete").resource("product")
                .action("delete").description("delete products").build();

        RolePermission rolePermission2 = RolePermission.builder().permission(writPermission).build();
        RolePermission rolePermission3 = RolePermission.builder().permission(deletePermission).build();

        adminRole.setRolePermissions(Set.of(rolePermission2, rolePermission3));

        UserRole userRoleMapping2 = UserRole.builder().role(adminRole).build();
        userRoles.add(userRoleMapping2);

        user.setUserRoles(userRoles);
        return user;
    }

    private User createUserWithoutRoles() {
        return User.builder().email(TEST_EMAIL).username(TEST_USERNAME)
                .passwordHash(TEST_PASSWORD_HASH).isActive(true).isLocked(false).build();
    }
}
