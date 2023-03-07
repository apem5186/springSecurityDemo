package com.example.springsecuritydemo.service.jwt;

import com.example.springsecuritydemo.entity.user.RefreshToken;
import com.example.springsecuritydemo.entity.user.User;
import com.example.springsecuritydemo.repository.RefreshTokenRepository;
import com.sun.security.auth.UserPrincipal;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenProvider {

    @Value("${app.jwtSecret}")
    private String jwtSecret;

    @Value("${app.jwtExpirationInMs}")
    private int jwtExpirationInMs;

    @Value("${app.refreshExpirationInMs}")
    private int refreshExpirationInMs;

    private final RefreshTokenRepository refreshTokenRepository;

    private Key getKey() {
        byte[] keyBytes = jwtSecret.getBytes();
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public AccessTokenResponse generateToken(Authentication authentication) {
        User userPrincipal = (User) authentication.getPrincipal();

        // Generate access token
        Date accessExpiryDate = Date.from(Instant.now().plusMillis(jwtExpirationInMs));
        String accessToken = Jwts.builder()
                .setSubject(userPrincipal.getId().toString())
                .setIssuedAt(new Date())
                .setExpiration(accessExpiryDate)
                .signWith(SignatureAlgorithm.HS512, getKey())
                .compact();

        // Generate refresh token
        Date refreshExpiryDate = Date.from(Instant.now().plusMillis(refreshExpirationInMs));
        String refreshToken = Jwts.builder()
                .setSubject(userPrincipal.getId().toString())
                .setIssuedAt(new Date())
                .setExpiration(refreshExpiryDate)
                .signWith(SignatureAlgorithm.HS512, getKey())
                .compact();

        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setUser(userPrincipal);
        refreshTokenEntity.setId(userPrincipal.getId());
        refreshTokenEntity.setToken(refreshToken);
        refreshTokenEntity.setExpiryDate(refreshExpiryDate.toInstant());
        refreshTokenRepository.save(refreshTokenEntity);

        return new AccessTokenResponse(accessToken, refreshToken);
    }

    public Long getUserIdFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

        return Long.parseLong(claims.getSubject());
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getKey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            System.out.println("Invalid JWT token");
        }
        return false;
    }

    public long getRefreshTokenExpirationInMillis() {
        return refreshExpirationInMs;
    }

    public long getAccessTokenExpirationInMillis() {
        return jwtExpirationInMs;
    }

    public LocalDateTime getTokenExpiration(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        Date expirationDate = claims.getExpiration();
        return LocalDateTime.ofInstant(expirationDate.toInstant(), ZoneId.systemDefault());
    }
}
