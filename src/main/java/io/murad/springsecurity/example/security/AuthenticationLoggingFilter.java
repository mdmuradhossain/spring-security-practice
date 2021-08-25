package io.murad.springsecurity.example.security;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthenticationLoggingFilter extends OncePerRequestFilter {

    private final Logger logger =
            LoggerFactory.getLogger(AuthenticationLoggingFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        String requestId = httpServletRequest.getHeader("Request-Id");
        logger.info("Successfully authenticated request with id " +
                requestId);
        filterChain.doFilter( httpServletRequest, httpServletResponse);
    }
}
