package com.example.springsecuritydemo.controller;

import com.example.springsecuritydemo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class MainController {

    private final UserRepository userRepository;

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/")
    public String root(Authentication authentication, Model model) {
        String email = userRepository.findByUsername(authentication.getName()).orElseThrow().getEmail();
        model.addAttribute("email", email);
        return "/public/main";
    }
}
