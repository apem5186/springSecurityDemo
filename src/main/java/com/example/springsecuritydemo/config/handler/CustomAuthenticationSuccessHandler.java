package com.example.springsecuritydemo.config.handler;

import com.example.springsecuritydemo.entity.user.User;
import com.example.springsecuritydemo.repository.UserRepository;
import com.example.springsecuritydemo.service.jwt.AccessTokenResponse;
import com.example.springsecuritydemo.service.jwt.TokenProvider;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

@Component
@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final TokenProvider tokenProvider;

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        AccessTokenResponse tokens = tokenProvider.generateToken(authentication);
        User user = userRepository.findByUsername(authentication.getName()).orElseThrow();
        user.setLogin(true);
        userRepository.save(user);
        String accessToken = tokens.getAccessToken();
        String refreshToken = tokens.getRefreshToken();

        response.setHeader("Authorization", "Bearer " + accessToken);

        Cookie cookie = new Cookie("accessToken", accessToken);
        cookie.setMaxAge(Math.toIntExact(TimeUnit.SECONDS.convert(tokenProvider.getAccessTokenExpirationInMillis(), TimeUnit.MILLISECONDS)));
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        response.addCookie(cookie);

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.toString());

        // TODO : Admin으로 회원가입은 되나 authentication.getAuthorities()에 "ROLE_USER"라 뜸
        if (AuthorityUtils.authorityListToSet(authentication.getAuthorities()).contains("ADMIN")) {
            log.info("================================");
            log.info("USER : " + authentication.getPrincipal());
            log.info("USER info : " + authentication.getAuthorities());
            log.info("ADMIN USER");
            log.info("================================");
            redirectStrategy.sendRedirect(request, response, "/admin");
        } else {
            log.info("USER : " + authentication.getPrincipal());
            log.info("USER info : " + authentication.getAuthorities());
            redirectStrategy.sendRedirect(request, response, "/");
        }
    }

}
