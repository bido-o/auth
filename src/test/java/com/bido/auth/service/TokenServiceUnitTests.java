package com.bido.auth.service;

import com.bido.auth.dto.AuthResponse;
import com.bido.auth.entity.RefreshToken;
import com.bido.auth.entity.User;
import com.bido.auth.entity.enums.UserRole;
import com.bido.auth.repository.RefreshTokenRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static com.bido.auth.utils.Statics.REFRESH_TOKEN_EXPIRATION_DAYS;
import static java.time.temporal.ChronoUnit.DAYS;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenServiceUnitTests {

    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private JwtService jwtService;

    @InjectMocks
    private TokenService tokenService;

    @Test
    void createTokenPair_Success() {
        User user = new User("test@bido.ro", UserRole.CLIENT);
        Instant exp = Instant.now().plus(REFRESH_TOKEN_EXPIRATION_DAYS, DAYS);
        when(jwtService.generateAccessToken(user)).thenReturn("jwt_token");

        AuthResponse response = tokenService.createTokenPair(user, exp);

        assertNotNull(response);
        assertEquals("jwt_token", response.accessToken());
        assertNotNull(response.refreshToken());

        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    void refreshAccessToken_Success_WithRotation() {
        User user = new User("test@bido.ro", UserRole.CLIENT);
        Instant originalExp = Instant.now().plus(20, DAYS);

        RefreshToken oldToken = new RefreshToken();
        oldToken.setToken("old_uuid");
        oldToken.setUser(user);
        oldToken.setExpiresAt(originalExp);

        when(refreshTokenRepository.findByToken("old_uuid")).thenReturn(Optional.of(oldToken));
        when(jwtService.generateAccessToken(user)).thenReturn("new_jwt");

        AuthResponse response = tokenService.refreshAccessToken("old_uuid");

        assertNotNull(response);
        assertEquals("new_jwt", response.accessToken());
        assertNotEquals("old_uuid", response.refreshToken());

        verify(refreshTokenRepository).delete(oldToken);

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(captor.capture());
        assertEquals(originalExp, captor.getValue().getExpiresAt());
    }

    @Test
    void refreshAccessToken_ThrowsException_IfExpired() {
        RefreshToken oldToken = new RefreshToken();
        oldToken.setExpiresAt(Instant.now().minus(1, DAYS));

        when(refreshTokenRepository.findByToken("old_uuid")).thenReturn(Optional.of(oldToken));

        assertThrows(RuntimeException.class, () -> tokenService.refreshAccessToken("old_uuid"));
        verify(refreshTokenRepository).delete(oldToken);
    }
}