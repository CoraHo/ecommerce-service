package com.coraho.ecommerceservice.service;

import com.coraho.ecommerceservice.entity.Permission;
import com.coraho.ecommerceservice.entity.Role;
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
    public Role addGroup(String name){
        if (groupRepository.existsByName(name)) {
            throw new IllegalArgumentException("Group already exists with name: " + name);
        }
        return groupRepository.save(Role.builder().name(name).build());
    }

    public Role findByName(String name) {
        return groupRepository.findByName(name).orElseThrow(
                () -> new RuntimeException("Group not found by name: " + name)
        );
    }

    @Transactional
    public Role addAuthoritiesToGroup(String groupName, String[] authorities) {
        Role role = findByName(groupName);

        for (String authorityName : authorities) {
            // add existing authorities to group
            Permission permission = authorityRepository.findByName(authorityName).orElseThrow(
                    () -> new RuntimeException("Authority not found with the name: " + authorityName)
            );
            role.getPermissions().add(permission);
            permission.getRoles().add(role);
            authorityRepository.save(permission);
        }
        groupRepository.save(role);
        return role;
    }

    @Transactional
    public Role updateGroup(Role role) {
        return groupRepository.save(role);
    }

}
