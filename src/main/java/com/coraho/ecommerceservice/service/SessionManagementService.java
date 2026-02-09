package com.coraho.ecommerceservice.service;

import java.util.List;
import java.util.Map;

import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.stereotype.Service;

import com.coraho.ecommerceservice.DTO.SessionInfo;
import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class SessionManagementService {

    private final FindByIndexNameSessionRepository<? extends Session> sessionRepository;
    private final UserRepository userRepository;

    // invalidate all sessions for a user
    public int invalidateAllUserSessions() {
        User user = getCurrentAuthenticatedUser();
        Map<String, ? extends Session> userSessions = sessionRepository.findByPrincipalName(user.getEmail());

        int count = 0;
        for (String key : userSessions.keySet()) {
            try {
                sessionRepository.deleteById(key);
                count++;
            } catch (Exception e) {
                log.warn("Failed to delete session {}: {}", key, e.getMessage());
            }
        }

        return count;
    }

    // invalidate all sessions except the current one
    public int invalidateAllUserSessionsExceptCurrent(String currentSessionId) {
        User user = getCurrentAuthenticatedUser();
        Map<String, ? extends Session> userSessions = sessionRepository.findByPrincipalName(user.getEmail());

        int count = 0;
        for (String key : userSessions.keySet()) {
            if (!key.equals(currentSessionId)) {
                try {
                    sessionRepository.deleteById(key);
                    count++;
                } catch (Exception e) {
                    log.warn("Failed to delete session {}: {}", key, e.getMessage());
                }
            }
        }
        return count;
    }

    // get count of active sessions for a user
    public int getTotalActiveSessionCount(String email) {
        return sessionRepository.findByPrincipalName(email).size();
    }

    // get all active sessions for a user
    public List<SessionInfo> getUserActiveSessionsInfo(String email) {
        Map<String, ? extends Session> userSessions = sessionRepository.findByPrincipalName(email);

        return userSessions.entrySet().stream()
                .map(entry -> SessionInfo.builder()
                        .sessionId(entry.getKey())
                        .creationTime(entry.getValue().getCreationTime())
                        .lastAccessTime(entry.getValue().getLastAccessedTime())
                        .build())
                .toList();
        // return a unmodifiable list to prevent the mutation on the list
    }

    // helper methods
    private User getCurrentAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new InsufficientAuthenticationException("User not logged in");
        }
        String email = authentication.getName();
        User currentUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return currentUser;
    }

}
