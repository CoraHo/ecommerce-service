package com.coraho.ecommerceservice;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;

@SpringBootTest
public class SpringSessionTest {

    @Autowired
    private FindByIndexNameSessionRepository<? extends Session> sessionRepository;

    @Test
    void testSpringSessionIsConfigured() {
        assertNotNull(sessionRepository, "Spring session is not configured");
        System.out.println("Session Repository type: " +
                sessionRepository.getClass().getName());
    }

}
