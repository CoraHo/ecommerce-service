package com.coraho.ecommerceservice.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name = "authorities")
public class Authority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long Id;

    @Column(length = 50, unique = true, nullable = false)
    private String name; // e.g. "READ_PRIVILEGE", "WRITE_PRIVILEGE"

    @ManyToMany(mappedBy = "authorities")
    private Set<Group> groups = new HashSet<>();
}
