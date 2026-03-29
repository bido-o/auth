package com.bido.auth.service;

import com.bido.auth.dto.AuthResponse;
import com.bido.auth.entity.LoginRateLimit;
import com.bido.auth.entity.RefreshToken;
import com.bido.auth.entity.User;
import com.bido.auth.entity.UserAuthToken;
import com.bido.auth.entity.enums.UserRole;
import com.bido.auth.repository.LoginRateLimitRepository;
import com.bido.auth.repository.RefreshTokenRepository;
import com.bido.auth.repository.UserAuthTokenRepository;
import com.bido.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;

import static java.time.temporal.ChronoUnit.MINUTES;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceUnitTests {

    @Mock private UserRepository userRepository;
    @Mock private UserAuthTokenRepository authTokenRepository;
    @Mock private LoginRateLimitRepository rateLimitRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private JwtService jwtService;
    @Mock private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthService authService;

    private final String TEST_EMAIL = "test@bido.ro";

    @BeforeEach
    void setUp() {
    }

    @Test
    void requestOtp_Success_ForNewUser() {
        // arrange
        when(rateLimitRepository.findById(TEST_EMAIL)).thenReturn(Optional.empty());
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArguments()[0]);
        when(passwordEncoder.encode(anyString())).thenReturn("hashed_otp");

        // act
        assertDoesNotThrow(() -> authService.requestOtp(TEST_EMAIL));

        // assert
        verify(userRepository, times(1)).save(any(User.class));
        verify(authTokenRepository, times(1)).deleteByEmail(TEST_EMAIL);

        ArgumentCaptor<UserAuthToken> tokenCaptor = ArgumentCaptor.forClass(UserAuthToken.class);
        verify(authTokenRepository).save(tokenCaptor.capture());

        UserAuthToken savedToken = tokenCaptor.getValue();
        assertEquals(TEST_EMAIL, savedToken.getEmail());
        assertEquals("hashed_otp", savedToken.getOtpCodeHash());
    }

    @Test
    void requestOtp_ThrowsException_IfUserSuspended() {
        // arrange
        User suspendedUser = new User(TEST_EMAIL, UserRole.CLIENT);
        suspendedUser.setSuspended(true);

        when(rateLimitRepository.findById(TEST_EMAIL)).thenReturn(Optional.empty());
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(suspendedUser));

        // act & assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.requestOtp(TEST_EMAIL));
        assertEquals("Acest cont este suspendat!", exception.getMessage());

        verify(authTokenRepository, never()).save(any());
    }

    @Test
    void requestOtp_ThrowsException_IfRateLimitExceeded() {
        // arrange
        LoginRateLimit limit = new LoginRateLimit();
        limit.setEmail(TEST_EMAIL);
        limit.setTokensRequested(5);
        limit.setLastAttemptAt(Instant.now().minus(2, MINUTES));

        when(rateLimitRepository.findById(TEST_EMAIL)).thenReturn(Optional.of(limit));

        // act & assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.requestOtp(TEST_EMAIL));
        assertTrue(exception.getMessage().contains("Ai cerut prea multe coduri OTP"));

        assertNotNull(limit.getBlockedUntil());
    }

    @Test
    void verifyOtp_Success() {
        // arrange
        String rawOtp = "123456";
        User user = new User(TEST_EMAIL, UserRole.CLIENT);

        UserAuthToken authToken = new UserAuthToken();
        authToken.setEmail(TEST_EMAIL);
        authToken.setOtpCodeHash("hashed_otp");
        authToken.setExpiresAt(Instant.now().plus(5, MINUTES));

        when(authTokenRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(authToken));
        when(passwordEncoder.matches(rawOtp, "hashed_otp")).thenReturn(true);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(user));
        when(jwtService.generateAccessToken(user)).thenReturn("mocked_jwt_token");

        // act
        AuthResponse response = authService.verifyOtp(TEST_EMAIL, rawOtp);

        // assert
        assertNotNull(response);
        assertEquals("mocked_jwt_token", response.accessToken());
        assertNotNull(response.refreshToken());

        verify(authTokenRepository, times(1)).delete(authToken);
        verify(rateLimitRepository, times(1)).deleteById(TEST_EMAIL);

        verify(refreshTokenRepository, times(1)).save(any(RefreshToken.class));
    }

    @Test
    void verifyOtp_ThrowsException_IfOtpIncorrect() {
        // arrange
        UserAuthToken authToken = new UserAuthToken();
        authToken.setEmail(TEST_EMAIL);
        authToken.setOtpCodeHash("hashed_otp");
        authToken.setExpiresAt(Instant.now().plus(5, MINUTES));

        when(authTokenRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(authToken));
        when(passwordEncoder.matches("wrong_otp", "hashed_otp")).thenReturn(false);

        // act & assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.verifyOtp(TEST_EMAIL, "wrong_otp"));
        assertEquals("Cod OTP incorect!", exception.getMessage());
    }
}