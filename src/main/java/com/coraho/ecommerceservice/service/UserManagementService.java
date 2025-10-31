package com.coraho.ecommerceservice.service;

import com.coraho.ecommerceservice.DTO.UserDTO;
import com.coraho.ecommerceservice.entity.User;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Service
@Transactional
public class UserManagementService {
    private final UserService userService;
    private final GroupService groupService;

    public UserManagementService(UserService userService, GroupService groupService) {
        this.userService = userService;
        this.groupService = groupService;
    }

    public User addUserWithRoles(UserDTO userDTO) {
        /* TODO */
        return null;
    }
}
