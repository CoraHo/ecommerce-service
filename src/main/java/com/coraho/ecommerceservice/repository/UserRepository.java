package com.coraho.ecommerceservice.repository;

import com.coraho.ecommerceservice.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    @Query("""
            SELECT u FROM User u
            WHERE u.username = :identifier OR u.email = :identifier
            """)
    Optional<User> findByUsernameOrEmail(@Param("identifier") String identifier);

    @Query("""
            SELECT u FROM User u
            LEFT JOIN FETCH u.userRoles ur
            LEFT JOIN FETCH ur.role r
            LEFT JOIN FETCH r.rolePermissions rp
            LEFT JOIN FETCH rp.permission
            WHERE u.username = :identifier OR u.email = :identifier
            """)
    Optional<User> findByUsernameOrEmailWithRolesAndPermissions(@Param("identifier") String identifier);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

}
