package com.example.springsecuritydemo.controller;

import com.example.springsecuritydemo.entity.user.RefreshToken;
import com.example.springsecuritydemo.entity.user.User;
import com.example.springsecuritydemo.repository.RefreshTokenRepository;
import com.example.springsecuritydemo.repository.UserRepository;
import com.example.springsecuritydemo.service.jwt.AccessTokenResponse;
import com.example.springsecuritydemo.service.jwt.TokenProvider;
import com.example.springsecuritydemo.service.jwt.TokenService;
import groovy.util.logging.Log;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.concurrent.TimeUnit;

@Slf4j
@Controller
@RequiredArgsConstructor
public class MainController {

    private final UserRepository userRepository;
    private final TokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenService tokenService;

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/")
    public String root(Authentication authentication, Model model, HttpServletRequest request,
                       HttpServletResponse response) {
        String result = tokenService.handleTokenOperations(authentication, model, request, response);

        if (result != null) {
            return result;
        }

        return "/public/main";
    }
}
