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
    void requestOtp_Success_NewUser() {
        // Arrange
        doNothing().when(otpService).checkAndApplyRateLimit(TEST_EMAIL);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());
        doNothing().when(otpService).generateAndSendOtp(TEST_EMAIL);

        // Act
        assertDoesNotThrow(() -> authService.requestOtp(TEST_EMAIL, UserRole.CLIENT));

        // Assert
        verify(userRepository).save(any(User.class));
        verify(otpService).generateAndSendOtp(TEST_EMAIL);
    }

    @Test
    void requestOtp_Success_ExistingUser() {
        // Arrange
        User existingUser = new User(TEST_EMAIL, UserRole.CLIENT);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(existingUser));

        // Act
        assertDoesNotThrow(() -> authService.requestOtp(TEST_EMAIL, null));

        // Assert
        verify(userRepository, never()).save(any());
        verify(otpService).generateAndSendOtp(TEST_EMAIL);
    }

    @Test
    void requestOtp_ThrowsException_IfNewUserAndRoleMissing() {
        // Arrange
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());

        // Act & Assert
        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> authService.requestOtp(TEST_EMAIL, null));

        assertEquals("Contul nu există. Te rugăm să selectezi un rol pentru înregistrare.", ex.getMessage());
        verify(otpService, never()).generateAndSendOtp(anyString());
    }

    @Test
    void requestOtp_ThrowsException_IfAdminRoleSelected() {
        // Arrange
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());

        // Act & Assert
        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> authService.requestOtp(TEST_EMAIL, UserRole.ADMIN));

        assertEquals("Rolul de Administrator nu poate fi ales la înregistrare.", ex.getMessage());
    }

    @Test
    void requestOtp_ThrowsException_IfSuspended() {
        // Arrange
        User suspendedUser = new User(TEST_EMAIL, UserRole.CLIENT);
        suspendedUser.setSuspended(true);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(suspendedUser));

        // Act & Assert
        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> authService.requestOtp(TEST_EMAIL, null));

        assertEquals("Acest cont este suspendat!", ex.getMessage());
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