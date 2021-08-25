package io.murad.springsecurity.example.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.server.csrf.CsrfToken;

import javax.servlet.*;
import java.io.IOException;

public class CSRFTokenLogger implements Filter {

    private Logger logger =
            LoggerFactory.getLogger(CSRFTokenLogger.class);

    @Override
    public void doFilter(
            ServletRequest request,
            ServletResponse response,
            FilterChain filterChain)
            throws IOException, ServletException {
        Object o = request.getAttribute("_csrf");
        CsrfToken token = (CsrfToken) o;
        logger.info("CSRF token " + token.getToken());
        filterChain.doFilter(request, response);
    }

}
