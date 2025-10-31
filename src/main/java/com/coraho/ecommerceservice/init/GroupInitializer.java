package com.coraho.ecommerceservice.init;

import com.coraho.ecommerceservice.service.GroupService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class GroupInitializer {
    private final GroupService groupService;

    @PostConstruct
    public void init(){
        groupService.addAuthoritiesToGroup("CUSTOMER", new String[] {"CUSTOMER_PRIVILEGE"});
        groupService.addAuthoritiesToGroup("ADMIN", new String[]{"ADMIN_PRIVILEGE"});
        groupService.addAuthoritiesToGroup("USER", new String[]{"USER_PRIVILEGE"});
    }
}
