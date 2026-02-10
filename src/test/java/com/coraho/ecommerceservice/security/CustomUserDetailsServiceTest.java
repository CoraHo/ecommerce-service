package com.coraho.ecommerceservice.security;

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.coraho.ecommerceservice.entity.Permission;
import com.coraho.ecommerceservice.entity.Role;
import com.coraho.ecommerceservice.entity.RolePermission;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.entity.UserRole;
import com.coraho.ecommerceservice.repository.UserRepository;

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

        RolePermission rolePermission1 = RolePermission.builder().permission(readPermission).role(userRole).build();
        userRole.setRolePermissions(Set.of(rolePermission1));
        readPermission.setRolePermissions(Set.of(rolePermission1));

        UserRole userRoleMapping1 = UserRole.builder().user(user).role(userRole).build();
        userRole.setUserRoles(Set.of(userRoleMapping1));
        userRoles.add(userRoleMapping1);

        // ROLE_ADMIN with product write and read permissions
        Role adminRole = Role.builder().name("ROLE_ADMIN").description("Admin user with all write and read previleges")
                .build();

        Permission writPermission = Permission.builder().name("product:write").resource("product")
                .action("write").description("write products").build();
        Permission deletePermission = Permission.builder().name("product:delete").resource("product")
                .action("delete").description("delete products").build();

        RolePermission rolePermission2 = RolePermission.builder().role(adminRole).permission(writPermission).build();
        RolePermission rolePermission3 = RolePermission.builder().role(adminRole).permission(deletePermission).build();

        adminRole.setRolePermissions(Set.of(rolePermission2, rolePermission3));
        writPermission.setRolePermissions(Set.of(rolePermission2));
        deletePermission.setRolePermissions(Set.of(rolePermission3));

        UserRole userRoleMapping2 = UserRole.builder().user(user).role(adminRole).build();
        adminRole.setUserRoles(Set.of(userRoleMapping2));
        userRoles.add(userRoleMapping2);

        user.setUserRoles(userRoles);
        return user;
    }
}
