package com.coraho.ecommerceservice.service;

import com.coraho.ecommerceservice.DTO.UserDTO;
import com.coraho.ecommerceservice.entity.Authority;
import com.coraho.ecommerceservice.entity.Group;
import com.coraho.ecommerceservice.entity.User;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

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
        Group group = groupService.findByName(groupName);
        user.getGroups().add(group);
        group.getUsers().add(user);
        userService.updateUser(user);
        groupService.updateGroup(group);
        return user;
    }
}
