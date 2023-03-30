package com.example.springsecuritydemo.config.handler;

import com.example.springsecuritydemo.repository.RefreshTokenRepository;
import com.example.springsecuritydemo.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class CustomLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("User logged out successfully.");
//        Long userId = userRepository.findByUsername(authentication.getName()).orElseThrow().getId();
//        log.info("USER ID : " + userId);
//        refreshTokenRepository.deleteByUserId(userId);
        super.onLogoutSuccess(request, response, authentication);
    }
}
