package com.coraho.ecommerceservice.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name = "role_groups")
public class Group {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 50, unique = true, nullable = false)
    private String name; // e.g. "ADMIN", "USER"

    @ManyToMany(mappedBy = "groups")
    private Set<User> users = new HashSet<>();


    @ManyToMany
    @JoinTable(
            name = "group_authorities",
            joinColumns = @JoinColumn(name="group_id"),
            inverseJoinColumns = @JoinColumn(name = "authorities_id")
    )
    private Set<Authority> authorities = new HashSet<>();
}
