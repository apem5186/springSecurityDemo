package com.example.springsecuritydemo.controller;

import com.example.springsecuritydemo.repository.RefreshTokenRepository;
import com.example.springsecuritydemo.repository.UserRepository;
import com.example.springsecuritydemo.service.jwt.TokenProvider;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.time.LocalDateTime;
import java.time.ZoneId;

@Controller
@RequiredArgsConstructor
public class MainController {

    private final UserRepository userRepository;
    private final TokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/")
    public String root(Authentication authentication, Model model, HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        String cookieValue = null;
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("accessToken")) {
                    cookieValue = cookie.getValue();
                    break;
                }
            }
        }
        Long userId = tokenProvider.getUserIdFromToken(cookieValue);
        LocalDateTime accessTokenExpiration = tokenProvider.getTokenExpiration(cookieValue);
        LocalDateTime refreshTokenExpiration = LocalDateTime.ofInstant(refreshTokenRepository.findByUserId(userId).orElseThrow().getExpiryDate(),
                ZoneId.systemDefault());
        String email = userRepository.findByUsername(authentication.getName()).orElseThrow().getEmail();
        model.addAttribute("accessTokenExpiration", accessTokenExpiration);
        model.addAttribute("refreshTokenExpiration", refreshTokenExpiration);
        model.addAttribute("email", email);
        return "/public/main";
    }
}
