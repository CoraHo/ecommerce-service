package com.coraho.ecommerceservice.security;

import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationFailureBadCredentialsEvent
                implements ApplicationListener<AuthenticationFailureBadCredentialsEvent> {

        @Override
        public void onApplicationEvent(AuthenticationFailureBadCredentialsEvent event) {
                // TODO Auto-generated method stub
                throw new UnsupportedOperationException("Unimplemented method 'onApplicationEvent'");
        }

}
