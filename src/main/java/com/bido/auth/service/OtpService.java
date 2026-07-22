package com.bido.auth.service;

import com.bido.auth.entity.LoginRateLimit;
import com.bido.auth.entity.UserAuthToken;
import com.bido.auth.exception.InvalidOtpException;
import com.bido.auth.exception.RateLimitException;
import com.bido.auth.repository.LoginRateLimitRepository;
import com.bido.auth.repository.UserAuthTokenRepository;
import com.bido.auth.utils.ErrorCodes;
import com.bido.auth.utils.ErrorMessages;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
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

    @Autowired
    public OtpService(LoginRateLimitRepository rateLimitRepository, UserAuthTokenRepository authTokenRepository) {
        this.rateLimitRepository = rateLimitRepository;
        this.authTokenRepository = authTokenRepository;
    }

    @Transactional(noRollbackFor = RateLimitException.class)
    public void checkAndApplyRateLimit(String email) {
        LoginRateLimit rateLimit = rateLimitRepository.findById(email)
                .orElseGet(() -> new LoginRateLimit(email));

        // is blocked
        if (rateLimit.getBlockedUntil() != null && Instant.now().isBefore(rateLimit.getBlockedUntil())) {
            long minutesLeft = MINUTES.between(Instant.now(), rateLimit.getBlockedUntil());
            throw new RateLimitException(ErrorCodes.RATE_LIMIT_BLOCKED, ErrorMessages.RATE_LIMIT_BLOCKED.formatted(minutesLeft));
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
            throw new RateLimitException(ErrorCodes.RATE_LIMIT_OTP, ErrorMessages.RATE_LIMIT_TOKENS);
        }

        rateLimitRepository.save(rateLimit);
    }

    @Transactional(noRollbackFor = InvalidOtpException.class)
    public void validateAndConsumeOtp(String email, String otpCode) {
        UserAuthToken authToken = authTokenRepository.findByEmail(email)
                .orElseThrow(() -> new InvalidOtpException(ErrorMessages.OTP_NOT_REQUESTED));

        if (authToken.getExpiresAt().isBefore(Instant.now())) {
            authTokenRepository.delete(authToken);
            throw new InvalidOtpException(ErrorMessages.OTP_EXPIRED);
        }

        if (!BCrypt.checkpw(otpCode, authToken.getOtpCodeHash())) {
            authToken.setAttemptsCount(authToken.getAttemptsCount() + 1);
            if (authToken.getAttemptsCount() >= MAX_OTP_ATTEMPTS) {
                authTokenRepository.delete(authToken);
                throw new InvalidOtpException(ErrorMessages.OTP_MAX_ATTEMPTS);
            } else {
                authTokenRepository.save(authToken);
                int remainingAttempts = MAX_OTP_ATTEMPTS - authToken.getAttemptsCount();
                throw new InvalidOtpException(ErrorMessages.OTP_INCORRECT.formatted(remainingAttempts));
            }
        }

        authTokenRepository.delete(authToken);
        rateLimitRepository.deleteById(email);
    }

    @Transactional
    public void generateAndSendOtp(String email) {
        String otpCode = generateSecureOtp();
        String hashedOtp = BCrypt.hashpw(otpCode, BCrypt.gensalt());

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
