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

import static com.bido.auth.utils.Statics.*;
import static java.time.temporal.ChronoUnit.MINUTES;

@Service
public class OtpService {

    private final LoginRateLimitRepository rateLimitRepository;
    private final UserAuthTokenRepository authTokenRepository;
    private final PasswordEncoder passwordEncoder;

    public OtpService(LoginRateLimitRepository rateLimitRepository,
                      UserAuthTokenRepository authTokenRepository, PasswordEncoder passwordEncoder) {
        this.rateLimitRepository = rateLimitRepository;
        this.authTokenRepository = authTokenRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public void checkAndApplyRateLimit(String email) {
        LoginRateLimit rateLimit = rateLimitRepository.findById(email)
                .orElseGet(() -> new LoginRateLimit(email));

        // is blocked
        if (rateLimit.getBlockedUntil() != null && Instant.now().isBefore(rateLimit.getBlockedUntil())) {
            long minutesLeft = MINUTES.between(Instant.now(), rateLimit.getBlockedUntil());
            throw new RuntimeException("Prea multe încercări. Cont blocat temporar pentru încă " + minutesLeft + " minute.");
        }

        // > 20 min from last attempt passed
        if (rateLimit.getLastAttemptAt().plus(SPAM_RESET_MINUTES, MINUTES).isBefore(Instant.now())) {
            rateLimit.setTokensRequested(0);
            rateLimit.setBlockedUntil(null);
        }

        rateLimit.setTokensRequested(rateLimit.getTokensRequested() + 1);
        rateLimit.setLastAttemptAt(Instant.now());

        if (rateLimit.getTokensRequested() > MAX_TOKENS_REQUESTED) {
            rateLimit.setBlockedUntil(Instant.now().plus(BLOCK_DURATION_MINUTES, MINUTES));
            rateLimitRepository.save(rateLimit);
            throw new RuntimeException("Ai cerut prea multe coduri OTP. Te rugăm să încerci din nou peste o" +
                    " oră.");
        }

        rateLimitRepository.save(rateLimit);
    }

    // TODO: use attempts count from auth token
    @Transactional
    public void validateAndConsumeOtp(String email, String otpCode) {
        UserAuthToken authToken = authTokenRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Nu a fost cerut niciun cod pentru acest email!"));

        if (authToken.getExpiresAt().isBefore(Instant.now())) {
            authTokenRepository.delete(authToken);
            throw new RuntimeException("Codul OTP a expirat. Te rugăm să ceri altul.");
        }

        // if 3 attempts -> delete token and throw

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

        UserAuthToken authToken = new UserAuthToken(email, hashedOtp,
                Instant.now().plus(OTP_EXPIRATION_MINUTES, MINUTES));

        authTokenRepository.save(authToken);

        // Simulăm trimiterea
        System.out.println("\n=====================================================");
        System.out.println("📩 EMAIL SIMULAT CĂTRE: " + email);
        System.out.println("🔑 CODUL TĂU DE LOGIN ESTE: " + otpCode);
        System.out.println("⏳ Codul expiră în " + OTP_EXPIRATION_MINUTES + " minute.");
        System.out.println("=====================================================\n");
    }

    private String generateSecureOtp() {
        SecureRandom random = new SecureRandom();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }
}
