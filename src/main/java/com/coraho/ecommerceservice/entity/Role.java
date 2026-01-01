package com.coraho.ecommerceservice.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name = "roles")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 50, unique = true, nullable = false)
    private String name; // e.g. "ADMIN", "USER"

    @Column
    private String description;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    // One-to-many relationship with UserRole
    @OneToMany(mappedBy = "role", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<UserRole> userRoles = new HashSet<>();

    // One-to-many relationship with RolePermission
    @OneToMany(mappedBy = "role", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<RolePermission> rolePermissions = new HashSet<>();

    // helper methods for mapping role-permission relationship
    public void addPermission(Permission permission){
        RolePermission rolePermission = new RolePermission();
        rolePermission.setRole(this);
        rolePermission.setPermission(permission);
        this.rolePermissions.add(rolePermission);
        permission.getRolePermissions().add(rolePermission);
    }

    public void removePermission(Permission permission) {
        RolePermission rolePermissionToBeRemoved = this.rolePermissions.stream()
                .filter(rp -> rp.getRole().equals(this) && rp.getPermission().equals(permission))
                .findFirst()
                .orElse(null);

        if (rolePermissionToBeRemoved != null) {
            this.rolePermissions.remove(rolePermissionToBeRemoved);
            permission.getRolePermissions().remove(rolePermissionToBeRemoved);
        }
    }

}
