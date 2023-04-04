package com.example.springsecuritydemo.controller;

import com.example.springsecuritydemo.entity.user.RefreshToken;
import com.example.springsecuritydemo.entity.user.User;
import com.example.springsecuritydemo.repository.RefreshTokenRepository;
import com.example.springsecuritydemo.repository.UserRepository;
import com.example.springsecuritydemo.service.jwt.AccessTokenResponse;
import com.example.springsecuritydemo.service.jwt.TokenProvider;
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

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/")
    public String root(Authentication authentication, Model model, HttpServletRequest request,
                       HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        String cookieValue = null;
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("accessToken") && tokenProvider.validateToken(cookie.getValue())) {
                    cookieValue = cookie.getValue();
                    log.info("-------------------------------");
                    log.info("COOKIE VALUE : " + cookieValue);
                    log.info("-------------------------------");
                    Long userId = tokenProvider.getUserIdFromToken(cookieValue);
                    LocalDateTime accessTokenExpiration = tokenProvider.getTokenExpiration(cookieValue);
                    LocalDateTime refreshTokenExpiration = LocalDateTime.ofInstant(refreshTokenRepository.findByUserId(userId).orElseThrow().getExpiryDate(),
                            ZoneId.systemDefault());
                    String email = userRepository.findByUsername(authentication.getName()).orElseThrow().getEmail();
                    model.addAttribute("accessTokenExpiration", accessTokenExpiration);
                    model.addAttribute("refreshTokenExpiration", refreshTokenExpiration);
                    model.addAttribute("email", email);
                    break;
                }
            }
            if (cookieValue == null) {
                String username = authentication.getName();
                Long uid = userRepository.findByUsername(username).orElseThrow().getId();
                String refreshToken = refreshTokenRepository.findByUserId(uid).orElseThrow().getToken();
                if (tokenProvider.validateToken(refreshToken)) {
                    User user = userRepository.findById(uid).orElseThrow(() -> new RuntimeException("User not found"));
                    authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                    AccessTokenResponse tokens = tokenProvider.generateToken(authentication);
                    String newAccessToken = tokens.getAccessToken();
                    String newRefreshToken = tokens.getRefreshToken();

                    refreshTokenRepository.deleteByUserId(uid);
                    RefreshToken refreshTokenEntity = new RefreshToken();
                    refreshTokenEntity.setUser(user);
                    refreshTokenEntity.setId(user.getId());
                    refreshTokenEntity.setToken(newRefreshToken);
                    refreshTokenEntity.setExpiryDate(Instant.now().plusMillis(tokenProvider.getRefreshTokenExpirationInMillis()));
                    refreshTokenRepository.save(refreshTokenEntity);

                    String email = userRepository.findByUsername(authentication.getName()).orElseThrow().getEmail();
                    model.addAttribute("accessTokenExpiration", tokenProvider.getTokenExpiration(newAccessToken));
                    model.addAttribute("refreshTokenExpiration", refreshTokenEntity.getExpiryDate());
                    model.addAttribute("email", email);
                    Cookie cookie = new Cookie("accessToken", newAccessToken);
                    cookie.setHttpOnly(true);
                    cookie.setMaxAge(Math.toIntExact(TimeUnit.SECONDS.convert(tokenProvider.getAccessTokenExpirationInMillis(),
                            TimeUnit.MILLISECONDS)));
                    cookie.setSecure(true);
                    cookie.setPath("/");
                    response.addCookie(cookie);
                } else {
                    model.addAttribute("reValidate", "refresh token이 만료되었습니다. 로그인 페이지로 이동합니다.");
                    log.info("reValidate message added to model: " + model.getAttribute("reValidate"));
                    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                    if (auth != null) {
                        refreshTokenRepository.deleteByUserId(uid);
                        return "redirect:/login";
                    }
                }
            }
        } else {
            String username = authentication.getName();
            Long uid = userRepository.findByUsername(username).orElseThrow().getId();
            String refreshToken = refreshTokenRepository.findByUserId(uid).orElseThrow().getToken();
            if (tokenProvider.validateToken(refreshToken)) {
                User user = userRepository.findById(uid).orElseThrow(() -> new RuntimeException("User not found"));
                authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                AccessTokenResponse tokens = tokenProvider.generateToken(authentication);
                String newAccessToken = tokens.getAccessToken();
                String newRefreshToken = tokens.getRefreshToken();

                refreshTokenRepository.deleteByUserId(uid);
                RefreshToken refreshTokenEntity = new RefreshToken();
                refreshTokenEntity.setUser(user);
                refreshTokenEntity.setId(user.getId());
                refreshTokenEntity.setToken(newRefreshToken);
                refreshTokenEntity.setExpiryDate(Instant.now().plusMillis(tokenProvider.getRefreshTokenExpirationInMillis()));
                refreshTokenRepository.save(refreshTokenEntity);

                String email = userRepository.findByUsername(authentication.getName()).orElseThrow().getEmail();
                model.addAttribute("accessTokenExpiration", tokenProvider.getTokenExpiration(newAccessToken));
                model.addAttribute("refreshTokenExpiration", refreshTokenEntity.getExpiryDate());
                model.addAttribute("email", email);
                Cookie cookie = new Cookie("accessToken", newAccessToken);
                cookie.setHttpOnly(true);
                cookie.setMaxAge(Math.toIntExact(TimeUnit.SECONDS.convert(tokenProvider.getAccessTokenExpirationInMillis(),
                        TimeUnit.MILLISECONDS)));
                cookie.setSecure(true);
                cookie.setPath("/");
                response.addCookie(cookie);
            } else {
                model.addAttribute("reValidate", "refresh token이 만료되었습니다. 로그인 페이지로 이동합니다.");
                log.info("reValidate message added to model: " + model.getAttribute("reValidate"));
                Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                if (auth != null) {
                    refreshTokenRepository.deleteByUserId(uid);
                    return "redirect:/login";
                }
            }
        }

        return "/public/main";
    }
}
