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

    public boolean checkGroupExistence(String name) {
        return groupRepository.existsByName(name);
    }

    @Transactional
    public Group addGroup(String name){
        if (groupRepository.existsByName(name)) {
            throw new IllegalArgumentException("Group already exists with name: " + name);
        }
        return groupRepository.save(Group.builder().name(name).build());
    }

    public Group findByName(String name) {
        return groupRepository.findByName(name).orElseThrow(
                () -> new RuntimeException("Group not found by name: " + name)
        );
    }

    @Transactional
    public Group addAuthoritiesToGroup(String groupName, String[] authorities) {
        Group group = findByName(groupName);

        for (String authorityName : authorities) {
            // add existing authorities to group
            Authority authority = authorityRepository.findByName(authorityName).orElseThrow(
                    () -> new RuntimeException("Authority not found with the name: " + authorityName)
            );
            group.getAuthorities().add(authority);
            authority.getGroups().add(group);
            authorityRepository.save(authority);
        }
        groupRepository.save(group);
        return group;
    }

    @Transactional
    public Group updateGroup(Group group) {
        return groupRepository.save(group);
    }

}
