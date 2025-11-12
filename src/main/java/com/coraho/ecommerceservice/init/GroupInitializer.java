package com.coraho.ecommerceservice.init;

import com.coraho.ecommerceservice.entity.Group;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.service.AuthorityService;
import com.coraho.ecommerceservice.service.GroupService;
import com.coraho.ecommerceservice.service.UserManagementService;
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
    private final UserManagementService userManagementService;

    @PostConstruct
    @Transactional
    public void init(){


        if(!authorityService.checkAuthorityExistence("ADMIN_PRIVILEGE") &&
                !authorityService.checkAuthorityExistence("USER_PRIVILEGE") &&
                !groupService.checkGroupExistence("ADMIN") &&
                !groupService.checkGroupExistence("USER") &&
                !userService.checkUserExistence("admin")) {
            // create authorities
            authorityService.addAuthority("ADMIN_PRIVILEGE");
            authorityService.addAuthority("USER_PRIVILEGE");

            // create groups
            groupService.addGroup("ADMIN");
            groupService.addGroup("USER");

            // create an admin user
            userService.registerUser("admin", "admin");

            // link groups with authorities
            groupService.addAuthoritiesToGroup("ADMIN", new String[]{"ADMIN_PRIVILEGE"});
            groupService.addAuthoritiesToGroup("USER", new String[]{"USER_PRIVILEGE"});

            // add the default admin user to ADMIN group
            User user = userManagementService.addUserToGroup("admin", "ADMIN");
            System.out.println(user.getUsername() + ", " + user.getPassword());
        }
    }
}
