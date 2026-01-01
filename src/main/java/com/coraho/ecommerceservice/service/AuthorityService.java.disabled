package com.coraho.ecommerceservice.service;

import com.coraho.ecommerceservice.entity.Permission;
import com.coraho.ecommerceservice.repository.AuthorityRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthorityService {
    private final AuthorityRepository authorityRepository;


    public Permission addAuthority(String name) {
        if (authorityRepository.existsByName(name)) {
            throw new IllegalArgumentException("Authority exists already with the name: " + name);
        }

        Permission permission = Permission.builder().name(name).build();
        return authorityRepository.save(permission);
    }

    public boolean checkAuthorityExistence(String name) {
        return authorityRepository.existsByName(name);
    }
}
