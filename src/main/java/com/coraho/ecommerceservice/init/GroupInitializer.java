package com.coraho.ecommerceservice.init;

import com.coraho.ecommerceservice.service.AuthorityService;
import com.coraho.ecommerceservice.service.GroupService;
import com.coraho.ecommerceservice.service.UserService;
import jakarta.annotation.PostConstruct;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class GroupInitializer {
    private final UserService userService;
    private final GroupService groupService;
    private final AuthorityService authorityService;

    @PostConstruct
    @Transactional
    public void init(){
        // create authorities
        authorityService.addAuthority("CUSTOMER_PRIVILEGE");
        authorityService.addAuthority("ADMIN_PRIVILEGE");
        authorityService.addAuthority("USER_PRIVILEGE");

        // create groups
        groupService.addGroup("CUSTOMER");
        groupService.addGroup("ADMIN");
        groupService.addGroup("USER");

        // create an admin user
        userService.registerUser("admin", "admin");

        // link groups with authorities
        groupService.addAuthoritiesToGroup("CUSTOMER", new String[] {"CUSTOMER_PRIVILEGE"});
        groupService.addAuthoritiesToGroup("ADMIN", new String[]{"ADMIN_PRIVILEGE"});
        groupService.addAuthoritiesToGroup("USER", new String[]{"USER_PRIVILEGE"});

        // add the default admin user to ADMIN group

    }
}
