package com.bido.auth.service;

import com.bido.auth.dto.AuthResponse;
import com.bido.auth.entity.User;
import com.bido.auth.entity.enums.UserRole;
import com.bido.auth.exception.AccountSuspendedException;
import com.bido.auth.exception.InvalidRoleException;
import com.bido.auth.exception.RateLimitException;
import com.bido.auth.exception.InvalidOtpException;
import com.bido.auth.repository.UserRepository;
import com.bido.auth.utils.ErrorMessages;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

import static com.bido.auth.utils.Statics.REFRESH_TOKEN_EXPIRATION_DAYS;
import static java.time.temporal.ChronoUnit.DAYS;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final OtpService otpService;
    private final TokenService tokenService;

    @Autowired
    public AuthService(UserRepository userRepository, OtpService otpService, TokenService tokenService) {
        this.userRepository = userRepository;
        this.otpService = otpService;
        this.tokenService = tokenService;
    }

    @Transactional(noRollbackFor = RateLimitException.class)
    public void requestOtp(String email, UserRole role) {

        resolveAndValidateUser(email, role);
        otpService.checkAndApplyRateLimit(email);
        otpService.generateAndSendOtp(email);
    }

    @Transactional(noRollbackFor = InvalidOtpException.class)
    public AuthResponse verifyOtp(String email, String otpCode) {

        otpService.validateAndConsumeOtp(email, otpCode);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User negăsit!"));

        user.setLastLoginAt(Instant.now());

        Instant expirationDate = Instant.now().plus(REFRESH_TOKEN_EXPIRATION_DAYS, DAYS);
        return tokenService.createTokenPair(user, expirationDate);
    }

    @Transactional
    public AuthResponse refreshToken(String refreshTokenString) {

        return tokenService.refreshAccessToken(refreshTokenString);
    }

    private void resolveAndValidateUser(String email, UserRole role) {
        Optional<User> userOpt = userRepository.findByEmail(email);

        if (userOpt.isEmpty()) {
            if (role == null) {
                throw new InvalidRoleException(ErrorMessages.ROLE_MISSING);
            }

            if (UserRole.ADMIN.equals(role)) {
                throw new InvalidRoleException(ErrorMessages.ROLE_ADMIN_INVALID);
            }

            userRepository.save(new User(email, role));
        } else {
            if (userOpt.get().isSuspended()) {
                throw new AccountSuspendedException(ErrorMessages.ACCOUNT_SUSPENDED);
            }
        }
    }
}