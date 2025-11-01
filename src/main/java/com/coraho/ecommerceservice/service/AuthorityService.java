package com.coraho.ecommerceservice.service;

import com.coraho.ecommerceservice.entity.Authority;
import com.coraho.ecommerceservice.repository.AuthorityRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthorityService {
    private final AuthorityRepository authorityRepository;


    public Authority addAuthority(String name) {
        if (authorityRepository.existsByName(name)) {
            throw new IllegalArgumentException("Authority exists already with the name: " + name);
        }

        Authority authority = Authority.builder().name(name).build();
        return authorityRepository.save(authority);
    }
}
