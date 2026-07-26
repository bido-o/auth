package com.bido.auth.service;

import com.bido.auth.dto.AuthResponse;
import com.bido.auth.entity.RefreshToken;
import com.bido.auth.entity.User;
import com.bido.auth.exception.AccountSuspendedException;
import com.bido.auth.exception.InvalidTokenException;
import com.bido.auth.repository.RefreshTokenRepository;
import com.bido.auth.utils.ErrorMessages;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
public class TokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;

    public TokenService(RefreshTokenRepository refreshTokenRepository, JwtService jwtService) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtService = jwtService;
    }

    @Transactional
    public AuthResponse createTokenPair(User user, Instant expirationDate) {
        String accessToken = jwtService.generateAccessToken(user);
        String refreshTokenValue = UUID.randomUUID().toString();

        RefreshToken refreshToken = new RefreshToken(user, refreshTokenValue, expirationDate);

        refreshTokenRepository.save(refreshToken);

        return new AuthResponse(accessToken, refreshTokenValue);
    }

    @Transactional(noRollbackFor = InvalidTokenException.class)
    public AuthResponse refreshAccessToken(String oldRefreshTokenString) {
        RefreshToken oldRefreshToken = refreshTokenRepository.findByToken(oldRefreshTokenString)
                .orElseThrow(() -> new InvalidTokenException(ErrorMessages.TOKEN_REFRESH_INVALID));

        if (oldRefreshToken.getExpiresAt().isBefore(Instant.now())) {
            refreshTokenRepository.delete(oldRefreshToken);
            throw new InvalidTokenException(ErrorMessages.TOKEN_EXPIRED);
        }

        User user = oldRefreshToken.getUser();

        // Blocare permanentă: un cont suspendat nu-și mai poate reînnoi sesiunea.
        if (user.isSuspended()) {
            throw new AccountSuspendedException(ErrorMessages.ACCOUNT_SUSPENDED);
        }

        refreshTokenRepository.delete(oldRefreshToken);

        return createTokenPair(user, oldRefreshToken.getExpiresAt());
    }
}
