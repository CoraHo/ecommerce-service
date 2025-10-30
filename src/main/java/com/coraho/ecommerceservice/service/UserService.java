package com.coraho.ecommerceservice.service;

import com.coraho.ecommerceservice.entity.Authority;
import com.coraho.ecommerceservice.entity.Group;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.repository.AuthorityRepository;
import com.coraho.ecommerceservice.repository.GroupRepository;
import com.coraho.ecommerceservice.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final GroupRepository groupRepository;
    private final AuthorityRepository authorityRepository;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, GroupRepository groupRepository,
                       AuthorityRepository authorityRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.groupRepository = groupRepository;
        this.authorityRepository = authorityRepository;
    }


    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    public User findUserByUsername(String username) {
        User user = userRepository.findByUsername(username).orElseThrow(
                () -> new UsernameNotFoundException("User not found by username: " + username)
        );

        return user;
    }

    public User registerCustomerUser(User user) {
        if (user.getUsername().isEmpty() || user.getPassword().isEmpty()) {
            throw new IllegalArgumentException("Username and Password are required");
        }
        if (userRepository.existsByUsername(user.getUsername())) {
            throw new IllegalArgumentException("This username already existed.");
        }
        /** set the group as customer */
        Group group = groupRepository.findByName("CUSTOMER").orElseGet(() -> {
            Group customerGroup = Group.builder().name("CUSTOMER").build();
            groupRepository.save(customerGroup);
            return customerGroup;
        });
        /** set up the authority as well */
        Authority authority = authorityRepository.findByName("CUSTOMER_PRIVILEGE").orElseGet(() -> {
            Authority customerAuthority = Authority.builder().name("CUSTOMER_PRIVILEGE").build();
            authorityRepository.save(customerAuthority);
            return customerAuthority;
        });
        /** link the user, customer group, and customer authority */
        addUserToGroup(user.getUsername(), group.getName());
        addAuthorityToGroup(group.getName(), authority.getName());

        /** encode password and add user to database */
        user.setPassword(passwordEncoder.encode(user.getUsername()));
        userRepository.save(user);

        return user;
    }

    public User addUserToGroup(String username, String groupName) {
        User user = userRepository.findByUsername(username).orElseThrow(
                () -> new UsernameNotFoundException("User not found by username: " + username)
        );
        Group group = groupRepository.findByName(groupName).orElseThrow(
                () -> new RuntimeException("Group not found by name: " + groupName)
        );
        user.getGroups().add(group);
        group.getUsers().add(user);
        userRepository.save(user);
        groupRepository.save(group);
    }

    public Group addAuthorityToGroup(String groupName, String authorityName) {
        Group group = groupRepository.findByName(groupName).orElseThrow(
                () -> new RuntimeException("Group not found by name: " + groupName)
        );
        Authority authority = authorityRepository.findByName(authorityName).orElseGet(() -> {
                    Authority customerAuthority = Authority.builder().name("CUSTOMER_PRIVILEGE").build();
                    authorityRepository.save(customerAuthority);
                    return customerAuthority;
                }
        );
        group.getAuthorities().add(authority);
        authority.getGroups().add(group);
        groupRepository.save(group);
        authorityRepository.save(authority);
    }
}
