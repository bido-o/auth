package com.bido.auth.service;

import com.bido.auth.dto.AuthResponse;
import com.bido.auth.entity.User;
import com.bido.auth.entity.enums.UserRole;
import com.bido.auth.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceUnitTests {

    @Mock private UserRepository userRepository;
    @Mock private OtpService otpService;
    @Mock private TokenService tokenService;

    @InjectMocks
    private AuthService authService;

    private final String TEST_EMAIL = "test@bido.ro";

    @Test
    void requestOtp_Success() {
        // Arrange
        doNothing().when(otpService).checkAndApplyRateLimit(TEST_EMAIL);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArguments()[0]);
        doNothing().when(otpService).generateAndSendOtp(TEST_EMAIL);

        // Act
        assertDoesNotThrow(() -> authService.requestOtp(TEST_EMAIL));

        // Assert
        verify(otpService).checkAndApplyRateLimit(TEST_EMAIL);
        verify(userRepository).save(any(User.class));
        verify(otpService).generateAndSendOtp(TEST_EMAIL);
    }

    @Test
    void requestOtp_ThrowsException_IfSuspended() {
        // Arrange
        User suspendedUser = new User(TEST_EMAIL, UserRole.CLIENT);
        suspendedUser.setSuspended(true);

        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(suspendedUser));

        // Act & Assert
        assertThrows(RuntimeException.class, () -> authService.requestOtp(TEST_EMAIL));
        verify(otpService, never()).generateAndSendOtp(anyString());
    }

    @Test
    void verifyOtp_Success() {
        // Arrange
        String rawOtp = "123456";
        User user = new User(TEST_EMAIL, UserRole.CLIENT);
        AuthResponse mockResponse = new AuthResponse("access", "refresh");

        doNothing().when(otpService).validateAndConsumeOtp(TEST_EMAIL, rawOtp);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(user));
        when(tokenService.createTokenPair(eq(user), any(Instant.class))).thenReturn(mockResponse);

        // Act
        AuthResponse response = authService.verifyOtp(TEST_EMAIL, rawOtp);

        // Assert
        assertNotNull(response);
        assertNotNull(user.getLastLoginAt());
        verify(tokenService).createTokenPair(eq(user), any(Instant.class));
    }
}