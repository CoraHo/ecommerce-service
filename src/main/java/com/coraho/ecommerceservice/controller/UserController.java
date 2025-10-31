package com.coraho.ecommerceservice.controller;

import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.repository.GroupRepository;
import com.coraho.ecommerceservice.service.GroupService;
import com.coraho.ecommerceservice.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
public class UserController {
    private final UserService userService;
    private final GroupService groupService;

    public UserController(UserService userService, GroupService groupService){
        this.userService = userService;
        this.groupService = groupService;
    }

    public ResponseEntity<User> createUserWithRoles() {
        /* TODO */
        return null;
    }

}
