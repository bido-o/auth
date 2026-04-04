package com.bido.auth.service;

import com.bido.auth.entity.LoginRateLimit;
import com.bido.auth.entity.UserAuthToken;
import com.bido.auth.repository.LoginRateLimitRepository;
import com.bido.auth.repository.UserAuthTokenRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;

import static com.bido.auth.utils.Statics.BLOCK_DURATION_MINUTES;
import static com.bido.auth.utils.Statics.MAX_TOKENS_REQUESTED;
import static java.time.temporal.ChronoUnit.MINUTES;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OtpServiceUnitTests {

    @Mock
    private LoginRateLimitRepository rateLimitRepository;

    @Mock
    private UserAuthTokenRepository authTokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private OtpService otpService;

    private final String TEST_EMAIL = "test@bido.ro";

    @Test
    void checkAndApplyRateLimit_Success_NormalRequest() {
        // Arrange
        LoginRateLimit limit = new LoginRateLimit(TEST_EMAIL);
        limit.setTokensRequested(2);

        when(rateLimitRepository.findById(TEST_EMAIL)).thenReturn(Optional.of(limit));

        // Act
        assertDoesNotThrow(() -> otpService.checkAndApplyRateLimit(TEST_EMAIL));

        // Assert
        assertEquals(3, limit.getTokensRequested());
        verify(rateLimitRepository).save(limit);
    }

    @Test
    void checkAndApplyRateLimit_ThrowsException_IfBlocked() {
        LoginRateLimit limit = new LoginRateLimit(TEST_EMAIL);
        limit.setBlockedUntil(Instant.now().plus(30, MINUTES));

        when(rateLimitRepository.findById(TEST_EMAIL)).thenReturn(Optional.of(limit));

        assertThrows(RuntimeException.class, () -> otpService.checkAndApplyRateLimit(TEST_EMAIL));
    }

    @Test
    void checkAndApplyRateLimit_ThrowsException_IfLimitReached() {
        LoginRateLimit limit = new LoginRateLimit(TEST_EMAIL);
        limit.setTokensRequested(MAX_TOKENS_REQUESTED);
        limit.setLastAttemptAt(Instant.now().minus(2, MINUTES));

        when(rateLimitRepository.findById(TEST_EMAIL)).thenReturn(Optional.of(limit));

        assertThrows(RuntimeException.class, () -> otpService.checkAndApplyRateLimit(TEST_EMAIL));
        assertNotNull(limit.getBlockedUntil());
    }

    @Test
    void checkAndApplyRateLimit_Success_ResetsAfter20Minutes() {
        // Arrange
        LoginRateLimit limit = new LoginRateLimit(TEST_EMAIL);
        limit.setTokensRequested(MAX_TOKENS_REQUESTED);
        limit.setLastAttemptAt(Instant.now().minus(25, MINUTES)); // MAGIA: Ultima încercare a fost acum 25 de minute!

        when(rateLimitRepository.findById(TEST_EMAIL)).thenReturn(Optional.of(limit));

        // Act
        assertDoesNotThrow(() -> otpService.checkAndApplyRateLimit(TEST_EMAIL));

        // Assert
        assertEquals(1, limit.getTokensRequested());
        verify(rateLimitRepository).save(limit);
    }

    @Test
    void checkAndApplyRateLimit_Success_BlockHasExpired() {
        // Arrange
        LoginRateLimit limit = new LoginRateLimit(TEST_EMAIL);
        limit.setTokensRequested(MAX_TOKENS_REQUESTED);
        limit.setBlockedUntil(Instant.now().minus(2, MINUTES));
        limit.setLastAttemptAt(Instant.now().minus(BLOCK_DURATION_MINUTES + 2, MINUTES));

        when(rateLimitRepository.findById(TEST_EMAIL)).thenReturn(Optional.of(limit));

        // Act
        assertDoesNotThrow(() -> otpService.checkAndApplyRateLimit(TEST_EMAIL));

        // Assert
        assertEquals(1, limit.getTokensRequested());
        assertNull(limit.getBlockedUntil());
        verify(rateLimitRepository).save(limit);
    }

    @Test
    void validateAndConsumeOtp_Success() {
        UserAuthToken token = new UserAuthToken();
        token.setOtpCodeHash("hash");
        token.setExpiresAt(Instant.now().plus(4, MINUTES));

        when(authTokenRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(token));
        when(passwordEncoder.matches("123456", "hash")).thenReturn(true);

        assertDoesNotThrow(() -> otpService.validateAndConsumeOtp(TEST_EMAIL, "123456"));

        verify(authTokenRepository).delete(token);
        verify(rateLimitRepository).deleteById(TEST_EMAIL);
    }

    @Test
    void validateAndConsumeOtp_ThrowsException_IfIncorrect() {
        UserAuthToken token = new UserAuthToken();
        token.setOtpCodeHash("hash");
        token.setExpiresAt(Instant.now().plus(4, MINUTES));

        when(authTokenRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(token));
        when(passwordEncoder.matches("wrong", "hash")).thenReturn(false);

        assertThrows(RuntimeException.class, () -> otpService.validateAndConsumeOtp(TEST_EMAIL, "wrong"));
        verify(authTokenRepository, never()).delete(any());
    }

    @Test
    void validateAndConsumeOtp_ThrowsException_IfExpired() {
        UserAuthToken expiredToken = new UserAuthToken(TEST_EMAIL, "some_opt_hash", Instant.now().minus(4, MINUTES));

        when(authTokenRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(expiredToken));

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> otpService.validateAndConsumeOtp(TEST_EMAIL, "123456"));

        assertEquals("Codul OTP a expirat. Te rugăm să ceri altul.", exception.getMessage());

        verify(authTokenRepository).delete(expiredToken);
    }

    @Test
    void generateAndSendOtp_Success() {
        // Arrange
        when(passwordEncoder.encode(anyString())).thenReturn("hashed_otp");

        // Act
        assertDoesNotThrow(() -> otpService.generateAndSendOtp(TEST_EMAIL));

        // Assert
        verify(authTokenRepository, times(1)).deleteByEmail(TEST_EMAIL);
        verify(authTokenRepository, times(1)).save(any(UserAuthToken.class));
    }
}