package com.coraho.ecommerceservice.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name = "permissions")
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long Id;

    @Column(length = 100, unique = true, nullable = false)
    private String name; // e.g. "READ_PRIVILEGE", "WRITE_PRIVILEGE"

    @Column(length = 100, nullable = false)
    private String resource;

    @Column(length = 50, nullable = false)
    private String action; // e.g. "WRITE", "READ"

    @Column
    private String description;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    // Many-to-Many relationship with Role
    @ManyToMany(mappedBy = "permissions", fetch = FetchType.LAZY)
    private Set<Role> roles = new HashSet<>();
}
