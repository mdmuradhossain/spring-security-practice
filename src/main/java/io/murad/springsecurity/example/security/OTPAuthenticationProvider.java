package io.murad.springsecurity.example.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class OTPAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private AuthenticationServerProxy proxy;


    @Override
    public Authentication authenticate
            (Authentication authentication)
            throws AuthenticationException {
        String username = authentication.getName();
        String code = String.valueOf(authentication.getCredentials());
        boolean result = proxy.sendOTP(username, code);
        if (result) {
            return new OTPAuthentication(username, code);
        } else {
            throw new BadCredentialsException("Bad credentials.");
        }

    }

    @Override
    public boolean supports(Class<?> aClass) {
        return OTPAuthentication.class.isAssignableFrom(aClass);
    }
}
