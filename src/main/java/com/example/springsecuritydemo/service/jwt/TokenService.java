package com.example.springsecuritydemo.service.jwt;

import com.example.springsecuritydemo.entity.user.RefreshToken;
import com.example.springsecuritydemo.entity.user.User;
import com.example.springsecuritydemo.repository.RefreshTokenRepository;
import com.example.springsecuritydemo.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class TokenService {
    private final UserRepository userRepository;
    private final TokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    public String handleTokenOperations(Authentication authentication, Model model, HttpServletRequest request,
                                        HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        String accessToken = null;
        Long userId;
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("accessToken") && tokenProvider.validateToken(cookie.getValue())) {
                    accessToken = cookie.getValue();
                    break;
                }
            }
        }

        if (accessToken == null) {
            String username = authentication.getName();
            userId = userRepository.findByUsername(username).orElseThrow().getId();
            String refreshToken = refreshTokenRepository.findByUserId(userId).orElseThrow().getToken();
            if (tokenProvider.validateToken(refreshToken)) {
                User user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
                authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                AccessTokenResponse tokens = tokenProvider.generateToken(authentication);
                accessToken = tokens.getAccessToken();
                String newRefreshToken = tokens.getRefreshToken();

                refreshTokenRepository.deleteByUserId(userId);
                RefreshToken refreshTokenEntity = new RefreshToken();
                refreshTokenEntity.setUser(user);
                refreshTokenEntity.setId(user.getId());
                refreshTokenEntity.setToken(newRefreshToken);
                refreshTokenEntity.setExpiryDate(Instant.now().plusMillis(tokenProvider.getRefreshTokenExpirationInMillis()));
                refreshTokenRepository.save(refreshTokenEntity);

                Cookie cookie = new Cookie("accessToken", accessToken);
                cookie.setHttpOnly(true);
                cookie.setMaxAge(Math.toIntExact(TimeUnit.SECONDS.convert(tokenProvider.getAccessTokenExpirationInMillis(),
                        TimeUnit.MILLISECONDS)));
                cookie.setSecure(true);
                cookie.setPath("/");
                response.addCookie(cookie);
            } else {
                return "redirect:/login";
            }
        }

        userId = tokenProvider.getUserIdFromToken(accessToken);
        LocalDateTime accessTokenExpiration = tokenProvider.getTokenExpiration(accessToken);
        LocalDateTime refreshTokenExpiration = LocalDateTime.ofInstant(refreshTokenRepository.findByUserId(userId).orElseThrow().getExpiryDate(),
                ZoneId.systemDefault());
        String email = userRepository.findByUsername(authentication.getName()).orElseThrow().getEmail();
        model.addAttribute("accessTokenExpiration", accessTokenExpiration);
        model.addAttribute("refreshTokenExpiration", refreshTokenExpiration);
        model.addAttribute("email", email);

        return null;
    }

}

