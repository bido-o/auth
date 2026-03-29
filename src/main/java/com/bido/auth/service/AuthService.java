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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final UserAuthTokenRepository authTokenRepository;
    private final LoginRateLimitRepository rateLimitRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository, UserAuthTokenRepository authTokenRepository,
                       LoginRateLimitRepository rateLimitRepository, RefreshTokenRepository refreshTokenRepository,
                       JwtService jwtService, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.authTokenRepository = authTokenRepository;
        this.rateLimitRepository = rateLimitRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public void requestOtp(String email) {

        checkAndApplyRateLimit(email);

        User user = userRepository.findByEmail(email)
                .orElseGet(() -> userRepository.save(new User(email, UserRole.CLIENT)));

        if (user.isSuspended()) {
            throw new RuntimeException("Acest cont este suspendat!");
        }

        generateAndSendOtp(email);
    }

    @Transactional
    public AuthResponse verifyOtp(String email, String otpCode) {
        UserAuthToken authToken = authTokenRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Nu a fost cerut niciun cod pentru acest email!"));

        if (authToken.getExpiresAt().isBefore(Instant.now())) {
            authTokenRepository.delete(authToken);
            throw new RuntimeException("Codul OTP a expirat. Te rugăm să ceri altul.");
        }

        if (!passwordEncoder.matches(otpCode, authToken.getOtpCodeHash())) {
            throw new RuntimeException("Cod OTP incorect!");
        }

        authTokenRepository.delete(authToken);

        rateLimitRepository.deleteById(email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User negăsit!"));

        user.setLastLoginAt(Instant.now());

        String accessToken = jwtService.generateAccessToken(user);
        String refreshTokenValue = UUID.randomUUID().toString();

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(refreshTokenValue);
        refreshToken.setExpiresAt(Instant.now().plus(30, ChronoUnit.DAYS));
        refreshTokenRepository.save(refreshToken);

        return new AuthResponse(accessToken, refreshTokenValue);
    }

    @Transactional
    public AuthResponse refreshToken(String refreshTokenString) {
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

    private void checkAndApplyRateLimit(String email) {
        LoginRateLimit rateLimit = rateLimitRepository.findById(email)
                .orElseGet(() -> {
                    LoginRateLimit newLimit = new LoginRateLimit();
                    newLimit.setEmail(email);
                    newLimit.setLastAttemptAt(Instant.now());
                    return newLimit;
                });

        if (rateLimit.getBlockedUntil() != null && Instant.now().isBefore(rateLimit.getBlockedUntil())) {
            long minutesLeft = ChronoUnit.MINUTES.between(Instant.now(), rateLimit.getBlockedUntil());
            throw new RuntimeException("Prea multe încercări. Cont blocat temporar pentru încă " + minutesLeft + " minute.");
        }

        if (rateLimit.getLastAttemptAt().plus(20, ChronoUnit.MINUTES).isBefore(Instant.now())) {
            rateLimit.setTokensRequested(0);
            rateLimit.setBlockedUntil(null);
        }

        rateLimit.setTokensRequested(rateLimit.getTokensRequested() + 1);
        rateLimit.setLastAttemptAt(Instant.now());

        if (rateLimit.getTokensRequested() > 5) {
            rateLimit.setBlockedUntil(Instant.now().plus(1, ChronoUnit.HOURS));
            rateLimitRepository.save(rateLimit);
            throw new RuntimeException("Ai cerut prea multe coduri OTP. Te rugăm să încerci din nou peste o oră.");
        }

        rateLimitRepository.save(rateLimit);
    }

    private void generateAndSendOtp(String email) {
        String otpCode = generateSecureOtp();
        String hashedOtp = passwordEncoder.encode(otpCode);

        authTokenRepository.deleteByEmail(email);

        UserAuthToken authToken = new UserAuthToken();
        authToken.setEmail(email);
        authToken.setOtpCodeHash(hashedOtp);
        authToken.setExpiresAt(Instant.now().plus(5, ChronoUnit.MINUTES));
        authToken.setAttemptsCount(0);

        authTokenRepository.save(authToken);

        // Simulăm trimiterea
        System.out.println("\n=====================================================");
        System.out.println("📩 EMAIL SIMULAT CĂTRE: " + email);
        System.out.println("🔑 CODUL TĂU DE LOGIN ESTE: " + otpCode);
        System.out.println("⏳ Codul expiră în 5 minute.");
        System.out.println("=====================================================\n");
    }

    private String generateSecureOtp() {
        SecureRandom random = new SecureRandom();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }
}