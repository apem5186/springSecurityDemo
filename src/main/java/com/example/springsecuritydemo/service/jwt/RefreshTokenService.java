package com.example.springsecuritydemo.service.jwt;

import com.example.springsecuritydemo.entity.user.RefreshToken;
import com.example.springsecuritydemo.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenProvider tokenProvider;

    public void saveRefreshToken(RefreshToken refreshToken) {
        refreshTokenRepository.save(refreshToken);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public void deleteRefreshToken(String token) {
        refreshTokenRepository.deleteByToken(token);
    }
}