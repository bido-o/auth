package com.bido.auth.service;

import com.bido.auth.dto.AuthResponse;
import com.bido.auth.entity.User;
import com.bido.auth.entity.enums.UserRole;
import com.bido.auth.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

import static java.time.temporal.ChronoUnit.DAYS;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final OtpService otpService;
    private final TokenService tokenService;

    public AuthService(UserRepository userRepository, OtpService otpService, TokenService tokenService) {
        this.userRepository = userRepository;
        this.otpService = otpService;
        this.tokenService = tokenService;
    }

    @Transactional
    public void requestOtp(String email) {

        otpService.checkAndApplyRateLimit(email);

        User user = userRepository.findByEmail(email)
                .orElseGet(() -> userRepository.save(new User(email, UserRole.CLIENT)));

        if (user.isSuspended()) {
            throw new RuntimeException("Acest cont este suspendat!");
        }

        otpService.generateAndSendOtp(email);
    }

    @Transactional
    public AuthResponse verifyOtp(String email, String otpCode) {

        otpService.validateAndConsumeOtp(email, otpCode);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User negăsit!"));

        user.setLastLoginAt(Instant.now());

        Instant expirationDate = Instant.now().plus(30, DAYS);
        return tokenService.createTokenPair(user, expirationDate);
    }

    @Transactional
    public AuthResponse refreshToken(String refreshTokenString) {

        return tokenService.refreshAccessToken(refreshTokenString);
    }
}