package com.example.springsecuritydemo.config.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class LogoutPreProcessingFilter extends OncePerRequestFilter {

    private final RequestMatcher logoutRequestMatcher;

    private static final Logger LOGGER = LoggerFactory.getLogger(LogoutPreProcessingFilter.class);

    public LogoutPreProcessingFilter(String logoutUrl) {
        this.logoutRequestMatcher = new AntPathRequestMatcher(logoutUrl);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        logger.info("Requested URL: " + request.getRequestURI());
        if (logoutRequestMatcher.matches(request)) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null) {
                logger.info("LOGOUT PRE AUTHENTICATION : " + authentication.getPrincipal());
                // Provide user information to the authentication system
                // For example: store user information in a request attribute
                request.setAttribute("user_info", authentication.getPrincipal());
            } else {
                logger.info("AUTHENTICATION IS NULL");
            }
        }

        filterChain.doFilter(request, response);
    }

}
