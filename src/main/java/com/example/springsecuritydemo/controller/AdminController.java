package com.example.springsecuritydemo.controller;

import com.example.springsecuritydemo.dto.SignUpDTO;
import com.example.springsecuritydemo.dto.UserModifyDTO;
import com.example.springsecuritydemo.entity.user.User;
import com.example.springsecuritydemo.repository.UserRepository;
import com.example.springsecuritydemo.service.jwt.TokenService;
import com.example.springsecuritydemo.service.user.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@Slf4j
@RequiredArgsConstructor
public class AdminController {

    private final TokenService tokenService;

    private final UserService userService;

    private final UserRepository userRepository;

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin")
    public String admin(Authentication authentication, Model model, HttpServletRequest request,
                        HttpServletResponse response) {

        String result = tokenService.handleTokenOperations(authentication, model, request, response);
        model.addAttribute("members", userService.userList());
        model.addAttribute("connectedMembers", userService.getConnectedUser());
        if (result != null) {
            return result;
        }

        return "/public/admin";

    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @PostMapping("/admin/deleteUser")
    public void deleteUser(@Valid Long userId, Model model, BindingResult bindingResult) {
        User user = userRepository.findById(userId).orElseThrow();
        try {
            userService.deleteUser(userId);
        } catch (Exception e) {
            bindingResult.reject("deleteUserFailed", e.getMessage());
        }
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @PostMapping("/admin/modifyUser")
    public void modifyUser(@Valid UserModifyDTO userModifyDTO, Model model, BindingResult bindingResult) {
        try {
            userService.modifyUser(userModifyDTO.getUserId(), userModifyDTO.getUsername(), userModifyDTO.getPassword(),
                    userModifyDTO.getEmail());
        } catch (Exception e) {
            bindingResult.reject("modifyUserFailed", e.getMessage());
        }
    }
}
