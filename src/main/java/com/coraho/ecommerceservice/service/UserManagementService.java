package com.coraho.ecommerceservice.service;

import com.coraho.ecommerceservice.entity.Role;
import com.coraho.ecommerceservice.entity.User;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

@Service
@Transactional
public class UserManagementService {
    private final UserService userService;
    private final GroupService groupService;

    public UserManagementService(UserService userService, GroupService groupService,
                                 AuthorityService authorityService) {
        this.userService = userService;
        this.groupService = groupService;
    }

    public User addUserToGroup(String username, String groupName) {
        User user = userService.findUserByUsername(username);
        Role role = groupService.findByName(groupName);
        user.getRoles().add(role);
        role.getUsers().add(user);
        userService.updateUser(user);
        groupService.updateGroup(role);
        return user;
    }
}
