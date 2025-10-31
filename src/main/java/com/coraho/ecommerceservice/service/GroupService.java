package com.coraho.ecommerceservice.service;

import com.coraho.ecommerceservice.entity.Authority;
import com.coraho.ecommerceservice.entity.Group;
import com.coraho.ecommerceservice.repository.AuthorityRepository;
import com.coraho.ecommerceservice.repository.GroupRepository;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

@Service
@Transactional
public class GroupService {
    private final GroupRepository groupRepository;
    private final AuthorityRepository authorityRepository;

    public GroupService(GroupRepository groupRepository, AuthorityRepository authorityRepository) {
        this.groupRepository = groupRepository;
        this.authorityRepository = authorityRepository;
    }

    @Transactional
    public Group addGroup(String name){
        if (groupRepository.existsByName(name)) {
            throw new IllegalArgumentException("Group already exists with name: " + name);
        }
        return groupRepository.save(Group.builder().name(name).build());
    }

    @Transactional
    public Group addAuthoritiesToGroup(String groupName, String[] authorities) {
        Group group = groupRepository.findByName(groupName).orElseThrow(
                () -> new RuntimeException("Group not found by name: " + groupName)
        );
        for (String authorityName : authorities) {
            Authority authority = authorityRepository.findByName(authorityName).orElseGet(() -> {
                        Authority customerAuthority = Authority.builder().name(authorityName).build();
                        authorityRepository.save(customerAuthority);
                        return customerAuthority;
                    }
            );
            group.getAuthorities().add(authority);
            authority.getGroups().add(group);
            groupRepository.save(group);
            authorityRepository.save(authority);
        }
        return group;
    }

}
