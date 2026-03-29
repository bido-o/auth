package com.bido.auth.service;

import com.bido.auth.dto.AuthResponse;
import com.bido.auth.entity.RefreshToken;
import com.bido.auth.entity.User;
import com.bido.auth.entity.UserAuthToken;
import com.bido.auth.entity.enums.UserRole;
import com.bido.auth.repository.RefreshTokenRepository;
import com.bido.auth.repository.UserAuthTokenRepository;
import com.bido.auth.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final UserAuthTokenRepository authTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository, UserAuthTokenRepository authTokenRepository, RefreshTokenRepository refreshTokenRepository, JwtService jwtService, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.authTokenRepository = authTokenRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public void requestOtp(String email) {
        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = new User(email, UserRole.CLIENT);
                    return userRepository.save(newUser);
                });

        if (user.isSuspended()) {
            throw new RuntimeException("Acest cont este suspendat!");
        }

        String otpCode = generateSecureOtp();

        String hashedOtp = passwordEncoder.encode(otpCode);

        authTokenRepository.deleteByEmail(email);

        UserAuthToken authToken = new UserAuthToken();
        authToken.setEmail(email);
        authToken.setOtpCodeHash(hashedOtp);
        authToken.setExpiresAt(Instant.now().plus(5, ChronoUnit.MINUTES));
        authToken.setAttemptsCount(0);

        authTokenRepository.save(authToken);

        System.out.println("\n=====================================================");
        System.out.println("📩 EMAIL SIMULAT CĂTRE: " + email);
        System.out.println("🔑 CODUL TĂU DE LOGIN ESTE: " + otpCode);
        System.out.println("⏳ Codul expiră în 5 minute.");
        System.out.println("=====================================================\n");
    }

    @Transactional
    public AuthResponse verifyOtp(String email, String otpCode) {
        // 1. Căutăm token-ul în baza de date
        UserAuthToken authToken = authTokenRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Nu a fost cerut niciun cod pentru acest email!"));

        // 2. Verificăm dacă a expirat
        if (authToken.getExpiresAt().isBefore(Instant.now())) {
            authTokenRepository.delete(authToken);
            throw new RuntimeException("Codul OTP a expirat. Te rugăm să ceri altul.");
        }

        // 3. Verificăm codul folosind BCrypt
        if (!passwordEncoder.matches(otpCode, authToken.getOtpCodeHash())) {
            // (Opțional: aici poți incrementa attemptsCount din authToken pentru limitarea atacurilor de tip Brute-Force)
            throw new RuntimeException("Cod OTP incorect!");
        }

        // 4. Codul este corect! Îl ștergem ca să nu mai poată fi folosit.
        authTokenRepository.delete(authToken);

        // 5. Luăm User-ul din baza de date
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User negăsit!"));

        // 6. Generăm Access Token (JWT)
        String accessToken = jwtService.generateAccessToken(user);

        // 7. Generăm Refresh Token (String Aleatoriu) și îl salvăm în DB
        String refreshTokenString = java.util.UUID.randomUUID().toString();

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setTokenHash(refreshTokenString); // Opțional poți face hash și aici, dar pentru UUID simplu e ok și clar
        refreshToken.setExpiresAt(Instant.now().plus(30, ChronoUnit.DAYS)); // Valabil 30 de zile

        refreshTokenRepository.save(refreshToken);

        // 8. Returnăm cele două chei către Frontend
        return new AuthResponse(accessToken, refreshTokenString);
    }

    @Transactional
    public AuthResponse refreshToken(String refreshTokenString) {
        // 1. Căutăm refresh token-ul exact în baza de date
        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(refreshTokenString)
                .orElseThrow(() -> new RuntimeException("Refresh Token invalid sau inexistent!"));

        // 2. Verificăm dacă a expirat (cele 30 de zile)
        if (refreshToken.getExpiresAt().isBefore(Instant.now())) {
            // Dacă a expirat, îl ștergem din DB și forțăm user-ul să se relogheze
            refreshTokenRepository.delete(refreshToken);
            throw new RuntimeException("Sesiunea a expirat. Te rugăm să te loghezi din nou.");
        }

        // 3. Token-ul este valid! Luăm user-ul atașat de el
        User user = refreshToken.getUser();

        // 4. Generăm un Access Token (JWT) complet nou (alte 15 minute)
        String newAccessToken = jwtService.generateAccessToken(user);

        // 5. Returnăm noul JWT și același Refresh Token (pe care îl mai poate folosi până expiră)
        return new AuthResponse(newAccessToken, refreshTokenString);
    }

    private String generateSecureOtp() {
        SecureRandom random = new SecureRandom();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }
}