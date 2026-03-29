package com.bido.auth.service;

import com.bido.auth.entity.LoginRateLimit;
import com.bido.auth.entity.UserAuthToken;
import com.bido.auth.repository.LoginRateLimitRepository;
import com.bido.auth.repository.UserAuthTokenRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;

import static java.time.temporal.ChronoUnit.HOURS;
import static java.time.temporal.ChronoUnit.MINUTES;

@Service
public class OtpService {


    private final LoginRateLimitRepository rateLimitRepository;
    private final UserAuthTokenRepository authTokenRepository;
    private final PasswordEncoder passwordEncoder;

    public OtpService(LoginRateLimitRepository rateLimitRepository, UserAuthTokenRepository authTokenRepository, PasswordEncoder passwordEncoder) {
        this.rateLimitRepository = rateLimitRepository;
        this.authTokenRepository = authTokenRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public void checkAndApplyRateLimit(String email) {
        LoginRateLimit rateLimit = rateLimitRepository.findById(email)
                .orElseGet(() -> {
                    LoginRateLimit newLimit = new LoginRateLimit();
                    newLimit.setEmail(email);
                    newLimit.setLastAttemptAt(Instant.now());
                    return newLimit;
                });

        if (rateLimit.getBlockedUntil() != null && Instant.now().isBefore(rateLimit.getBlockedUntil())) {
            long minutesLeft = MINUTES.between(Instant.now(), rateLimit.getBlockedUntil());
            throw new RuntimeException("Prea multe încercări. Cont blocat temporar pentru încă " + minutesLeft + " minute.");
        }

        if (rateLimit.getLastAttemptAt().plus(20, MINUTES).isBefore(Instant.now())) {
            rateLimit.setTokensRequested(0);
            rateLimit.setBlockedUntil(null);
        }

        rateLimit.setTokensRequested(rateLimit.getTokensRequested() + 1);
        rateLimit.setLastAttemptAt(Instant.now());

        if (rateLimit.getTokensRequested() > 5) {
            rateLimit.setBlockedUntil(Instant.now().plus(1, HOURS));
            rateLimitRepository.save(rateLimit);
            throw new RuntimeException("Ai cerut prea multe coduri OTP. Te rugăm să încerci din nou peste o oră.");
        }

        rateLimitRepository.save(rateLimit);
    }

    @Transactional
    public void validateAndConsumeOtp(String email, String otpCode) {
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
    }

    @Transactional
    public void generateAndSendOtp(String email) {
        String otpCode = generateSecureOtp();
        String hashedOtp = passwordEncoder.encode(otpCode);

        authTokenRepository.deleteByEmail(email);

        UserAuthToken authToken = new UserAuthToken();
        authToken.setEmail(email);
        authToken.setOtpCodeHash(hashedOtp);
        authToken.setExpiresAt(Instant.now().plus(5, MINUTES));
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
