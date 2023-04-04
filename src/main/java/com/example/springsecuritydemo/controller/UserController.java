package com.example.springsecuritydemo.controller;

import com.example.springsecuritydemo.config.handler.CustomLogoutSuccessHandler;
import com.example.springsecuritydemo.dto.SignUpDTO;
import com.example.springsecuritydemo.entity.user.RefreshToken;
import com.example.springsecuritydemo.entity.user.User;
import com.example.springsecuritydemo.repository.RefreshTokenRepository;
import com.example.springsecuritydemo.repository.UserRepository;
import com.example.springsecuritydemo.service.jwt.AccessTokenResponse;
import com.example.springsecuritydemo.service.jwt.TokenProvider;
import com.example.springsecuritydemo.service.user.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

@Controller
@Slf4j
@RequiredArgsConstructor
public class UserController {
    private final UserRepository userRepository;

    private final UserService userService;

    private final TokenProvider tokenProvider;

    private final AuthenticationManager authenticationManager;

    private final RefreshTokenRepository refreshTokenRepository;

    @PostMapping("/reissue")
    public String reissue(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException, ServletException {
        String accessToken = getAccessTokenFromCookie(request);
        Long userId = null;
        if (accessToken == null) {
            String username = SecurityContextHolder.getContext().getAuthentication().getName();
            userId = userRepository.findByUsername(username).orElseThrow().getId();
        } else {
            userId = tokenProvider.getUserIdFromToken(accessToken);
        }
        log.info("ACCESS TOKEN : " + accessToken);
        log.info("USER ID : " + userId);
        String refreshToken = refreshTokenRepository.findByUserId(userId).orElseThrow().getToken();
        log.info("REFRESH TOKEN : " + refreshToken);
        if (!tokenProvider.validateToken(accessToken)) {
            if (!tokenProvider.validateToken(refreshToken)) {
                model.addAttribute("reValidate", "refresh token이 만료되었습니다. 로그인 페이지로 이동합니다.");
                log.info("reValidate message added to model: " + model.getAttribute("reValidate"));
                Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                if (auth != null) {
                    refreshTokenRepository.deleteByUserId(userId);
                }
                    return "redirect:/login";
            }
        }

        User user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
        AccessTokenResponse tokens = tokenProvider.generateToken(authentication);
        String newAccessToken = tokens.getAccessToken();
        String newRefreshToken = tokens.getRefreshToken();

        refreshTokenRepository.deleteByUserId(userId);
        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setUser(user);
        refreshTokenEntity.setId(user.getId());
        refreshTokenEntity.setToken(newRefreshToken);
        refreshTokenEntity.setExpiryDate(Instant.now().plusMillis(tokenProvider.getRefreshTokenExpirationInMillis()));
        refreshTokenRepository.save(refreshTokenEntity);

        Cookie cookie = new Cookie("accessToken", newAccessToken);
        cookie.setHttpOnly(true);
        cookie.setMaxAge(Math.toIntExact(TimeUnit.SECONDS.convert(tokenProvider.getAccessTokenExpirationInMillis(),
                TimeUnit.MILLISECONDS)));
        cookie.setSecure(true);
        cookie.setPath("/");
        response.addCookie(cookie);

        return "redirect:/";

    }

    private String checkLoggedInFromRefreshToken(String username) {

        Long userId = userRepository.findByUsername(username).orElseThrow().getId();
        if (refreshTokenRepository.findByUserId(userId).isPresent()) {

        }
        return null;
    }
    private String getAccessTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("accessToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

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
