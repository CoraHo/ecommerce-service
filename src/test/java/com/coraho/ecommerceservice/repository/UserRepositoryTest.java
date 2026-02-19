package com.coraho.ecommerceservice.repository;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import com.coraho.ecommerceservice.entity.Permission;
import com.coraho.ecommerceservice.entity.Role;
import com.coraho.ecommerceservice.entity.RolePermission;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.entity.UserRole;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
@DisplayName("UserRepository Tests")
public class UserRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;
    @Autowired
    private UserRepository userRepository;
    private User user;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .username("johndoe")
                .email("john@example.com")
                .passwordHash("secret")
                .build();
        entityManager.persistAndFlush(user);
    }

    // --- findByUsername ---

    @Test
    @DisplayName("Should return user when user name exists")
    void findByUsername_shouldReturnUserWhenUsernameExists() {
        Optional<User> result = userRepository.findByUsername("johndoe");

        assertThat(result).isPresent();
        assertThat(result.get().getUsername()).isEqualTo("johndoe");
    }

    @Test
    @DisplayName("Should return empty when username not exists")
    void findByUsername_shouldReturnEmpty_whenUsernameNotExists() {
        Optional<User> result = userRepository.findByUsername("unknown");

        assertThat(result).isEmpty();
    }

    // --- findByEmail ---

    @Test
    void findByEmail_shouldReturnUser_whenEmailExists() {
        Optional<User> result = userRepository.findByEmail("john@example.com");

        assertThat(result).isPresent();
        assertThat(result.get().getEmail()).isEqualTo("john@example.com");
    }

    @Test
    void findByEmail_shouldReturnEmpty_whenEmailNotExists() {
        Optional<User> result = userRepository.findByEmail("nobody@example.com");

        assertThat(result).isEmpty();
    }

    // --- findByUsernameOrEmail ---
    @Test
    void findByUsernameOrEmail_shouldReturnUserwhenSearchByUsername() {
        Optional<User> result = userRepository.findByUsernameOrEmail("johndoe");

        assertThat(result).isPresent();
        assertThat(result.get().getUsername()).isEqualTo("johndoe");
    }

    @Test
    void findByUsernameOrEmail_shouldReturnUser_whenSearchByEmail() {
        Optional<User> result = userRepository.findByUsernameOrEmail("john@example.com");

        assertThat(result).isPresent();
        assertThat(result.get().getEmail()).isEqualTo("john@example.com");
    }

    @Test
    void findByUsernameOrEmail_shouldReturnEmpty_whenIdentifierNotExists() {
        Optional<User> result = userRepository.findByUsernameOrEmail("notexist");

        assertThat(result).isEmpty();
    }

    // --- findByUsernameOrEmailWithRolesAndPermissions ---
    void findByUsernameOrEmailWithRolesAndPermissions_shouldReturnUserWithRolesAndPermissionsWhenSearchByUsername() {
        Permission p = Permission.builder().name("product:read").build();
        entityManager.persistAndFlush(p);
        Role r = Role.builder().name("ROLE_USER").build();
        entityManager.persistAndFlush(r);
        RolePermission rp = RolePermission.builder().role(r).permission(p).build();
        entityManager.persistAndFlush(rp);
        UserRole ur = UserRole.builder().user(user).role(r).build();
        entityManager.persistAndFlush(ur);

        // Clear the cache
        entityManager.clear();

        Optional<User> result = userRepository.findByUsernameOrEmailWithRolesAndPermissions("johndoe");

        assertThat(result).isPresent();
        assertThat(result.get().getUsername()).isEqualTo("johndoe");
        assertThat(result.get().getUserRoles()).isNotEmpty();
        assertThat(result.get().getUserRoles()).flatExtracting(userRole -> userRole.getRole().getRolePermissions())
                .isNotEmpty();
    }

    @Test
    void findByUsernameOrEmailWithRolesAndPermissions_shouldReturnEmpty_whenNotFound() {
        Optional<User> result = userRepository
                .findByUsernameOrEmailWithRolesAndPermissions("ghost");

        assertThat(result).isEmpty();
    }

    // --- existsByUsername ---

    @Test
    void existsByUsername_shouldReturnTrue_whenUsernameExists() {
        assertThat(userRepository.existsByUsername("johndoe")).isTrue();
    }

    @Test
    void existsByUsername_shouldReturnFalse_whenUsernameNotExists() {
        assertThat(userRepository.existsByUsername("ghost")).isFalse();
    }

    // --- existsByEmail ---

    @Test
    void existsByEmail_shouldReturnTrue_whenEmailExists() {
        assertThat(userRepository.existsByEmail("john@example.com")).isTrue();
    }

    @Test
    void existsByEmail_shouldReturnFalse_whenEmailNotExists() {
        assertThat(userRepository.existsByEmail("ghost@example.com")).isFalse();
    }
}
