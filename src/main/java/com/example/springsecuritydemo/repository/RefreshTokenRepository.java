package com.example.springsecuritydemo.repository;

import com.example.springsecuritydemo.entity.user.RefreshToken;
import com.example.springsecuritydemo.service.jwt.AccessTokenResponse;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    Optional<RefreshToken> findByUserId(Long userId);

    @Transactional
    void deleteByUserId(Long userId);

    @Transactional
    void deleteByToken(String token);
}
