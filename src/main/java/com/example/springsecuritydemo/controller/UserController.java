package com.example.springsecuritydemo.controller;

import com.example.springsecuritydemo.dto.SignUpDTO;
import com.example.springsecuritydemo.entity.user.User;
import com.example.springsecuritydemo.service.user.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/login")
    public String login() {
        return "public/login";
    }

    @GetMapping("/signUp")
    public String signUp(Model model) {
        model.addAttribute("signupDto", new SignUpDTO());
        return "public/signUp";
    }

    @PostMapping("/signUp")
    public String signUp(@Valid SignUpDTO signUpDTO, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return "public/signUp";
        }

        if (!signUpDTO.getPassword1().equals(signUpDTO.getPassword2())) {
            bindingResult.rejectValue("password2", "passwordInCorrect",
                    "2개의 비밀번호가 일치하지 않습니다.");
            return "public/signUp";
        }

        try {
            userService.signUp(signUpDTO.getUsername(), signUpDTO.getEmail(), signUpDTO.getPassword1());
        } catch (DataIntegrityViolationException e) {
            e.printStackTrace();
            bindingResult.reject("signupFailed", "이미 등록된 사용자입니다.");
            return "public/signUp";
        } catch (Exception e) {
            e.printStackTrace();
            bindingResult.reject("signupFailed", e.getMessage());
            return "public/signUp";
        }

        return "redirect:/login";
    }
}
