package com.bido.auth.service;

import com.bido.auth.dto.AuthResponse;
import com.bido.auth.entity.RefreshToken;
import com.bido.auth.entity.User;
import com.bido.auth.repository.RefreshTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

import static java.time.temporal.ChronoUnit.DAYS;

@Service
public class TokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;

    public TokenService(RefreshTokenRepository refreshTokenRepository, JwtService jwtService) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtService = jwtService;
    }

    @Transactional
    public AuthResponse createTokenPair(User user) {
        String accessToken = jwtService.generateAccessToken(user);
        String refreshTokenValue = UUID.randomUUID().toString();

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(refreshTokenValue);
        refreshToken.setExpiresAt(Instant.now().plus(30, DAYS));

        refreshTokenRepository.save(refreshToken);

        return new AuthResponse(accessToken, refreshTokenValue);
    }

    @Transactional
    public AuthResponse refreshAccessToken(String refreshTokenString) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenString)
                .orElseThrow(() -> new RuntimeException("Refresh Token invalid sau inexistent!"));

        if (refreshToken.getExpiresAt().isBefore(Instant.now())) {
            refreshTokenRepository.delete(refreshToken);
            throw new RuntimeException("Sesiunea a expirat. Te rugăm să te loghezi din nou.");
        }

        User user = refreshToken.getUser();
        String newAccessToken = jwtService.generateAccessToken(user);

        return new AuthResponse(newAccessToken, refreshTokenString);
    }
}
