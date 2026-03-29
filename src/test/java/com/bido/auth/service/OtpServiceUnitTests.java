package com.bido.auth.service;

import com.bido.auth.entity.LoginRateLimit;
import com.bido.auth.entity.UserAuthToken;
import com.bido.auth.repository.LoginRateLimitRepository;
import com.bido.auth.repository.UserAuthTokenRepository;
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
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OtpServiceUnitTests {

    @Mock private LoginRateLimitRepository rateLimitRepository;
    @Mock private UserAuthTokenRepository authTokenRepository;
    @Mock private PasswordEncoder passwordEncoder;

    @InjectMocks
    private OtpService otpService;

    private final String TEST_EMAIL = "test@bido.ro";

    @Test
    void checkAndApplyRateLimit_ThrowsException_IfBlocked() {
        LoginRateLimit limit = new LoginRateLimit();
        limit.setEmail(TEST_EMAIL);
        limit.setBlockedUntil(Instant.now().plus(30, MINUTES)); // E blocat încă 30 min

        when(rateLimitRepository.findById(TEST_EMAIL)).thenReturn(Optional.of(limit));

        assertThrows(RuntimeException.class, () -> otpService.checkAndApplyRateLimit(TEST_EMAIL));
    }

    @Test
    void checkAndApplyRateLimit_ThrowsException_IfLimitReached() {
        LoginRateLimit limit = new LoginRateLimit();
        limit.setEmail(TEST_EMAIL);
        limit.setTokensRequested(5); // E la limită
        limit.setLastAttemptAt(Instant.now().minus(2, MINUTES));

        when(rateLimitRepository.findById(TEST_EMAIL)).thenReturn(Optional.of(limit));

        assertThrows(RuntimeException.class, () -> otpService.checkAndApplyRateLimit(TEST_EMAIL));
        assertNotNull(limit.getBlockedUntil()); // S-a pus block-ul?
    }

    @Test
    void validateAndConsumeOtp_Success() {
        UserAuthToken token = new UserAuthToken();
        token.setOtpCodeHash("hash");
        token.setExpiresAt(Instant.now().plus(5, MINUTES));

        when(authTokenRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(token));
        when(passwordEncoder.matches("123456", "hash")).thenReturn(true);

        assertDoesNotThrow(() -> otpService.validateAndConsumeOtp(TEST_EMAIL, "123456"));

        verify(authTokenRepository).delete(token); // A fost șters?
        verify(rateLimitRepository).deleteById(TEST_EMAIL); // S-a curățat istoricul?
    }

    @Test
    void validateAndConsumeOtp_ThrowsException_IfIncorrect() {
        UserAuthToken token = new UserAuthToken();
        token.setOtpCodeHash("hash");
        token.setExpiresAt(Instant.now().plus(5, MINUTES));

        when(authTokenRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(token));
        when(passwordEncoder.matches("wrong", "hash")).thenReturn(false);

        assertThrows(RuntimeException.class, () -> otpService.validateAndConsumeOtp(TEST_EMAIL, "wrong"));
        verify(authTokenRepository, never()).delete(any()); // Tokenul NU se șterge dacă e greșit
    }

    @Test
    void generateAndSendOtp_Success() {
        // Arrange
        when(passwordEncoder.encode(anyString())).thenReturn("hashed_otp");

        // Act
        assertDoesNotThrow(() -> otpService.generateAndSendOtp(TEST_EMAIL));

        // Assert
        verify(authTokenRepository, times(1)).deleteByEmail(TEST_EMAIL); // A făcut curat înainte?
        verify(authTokenRepository, times(1)).save(any(UserAuthToken.class)); // A salvat noul token?
    }

    @Test
    void checkAndApplyRateLimit_Success_NormalRequest() {
        // Arrange
        LoginRateLimit limit = new LoginRateLimit();
        limit.setEmail(TEST_EMAIL);
        limit.setTokensRequested(2); // A mai cerut 2 coduri, mai are voie
        limit.setLastAttemptAt(Instant.now());

        when(rateLimitRepository.findById(TEST_EMAIL)).thenReturn(Optional.of(limit));

        // Act
        assertDoesNotThrow(() -> otpService.checkAndApplyRateLimit(TEST_EMAIL));

        // Assert
        assertEquals(3, limit.getTokensRequested()); // A crescut contorul la 3?
        verify(rateLimitRepository).save(limit);
    }

    @Test
    void checkAndApplyRateLimit_Success_ResetsAfter20Minutes() {
        // Arrange
        LoginRateLimit limit = new LoginRateLimit();
        limit.setEmail(TEST_EMAIL);
        limit.setTokensRequested(5); // Era la limita maximă de spam
        limit.setBlockedUntil(null); // Nu e blocat permanent
        limit.setLastAttemptAt(Instant.now().minus(25, MINUTES)); // MAGIA: Ultima încercare a fost acum 25 de minute!

        when(rateLimitRepository.findById(TEST_EMAIL)).thenReturn(Optional.of(limit));

        // Act
        assertDoesNotThrow(() -> otpService.checkAndApplyRateLimit(TEST_EMAIL));

        // Assert
        // Contorul trebuia să se reseteze la 0, iar apoi să se adune +1 pentru cererea curentă.
        assertEquals(1, limit.getTokensRequested());
        verify(rateLimitRepository).save(limit);
    }

    @Test
    void checkAndApplyRateLimit_Success_ForNewUser() {
        // Arrange: Simulăm că baza de date nu găsește niciun istoric pentru acest email
        when(rateLimitRepository.findById(TEST_EMAIL)).thenReturn(Optional.empty());

        // Act
        assertDoesNotThrow(() -> otpService.checkAndApplyRateLimit(TEST_EMAIL));

        // Assert: Capturăm obiectul creat în orElseGet ca să vedem dacă l-a inițializat corect
        ArgumentCaptor<LoginRateLimit> captor = ArgumentCaptor.forClass(LoginRateLimit.class);
        verify(rateLimitRepository).save(captor.capture());

        assertEquals(TEST_EMAIL, captor.getValue().getEmail());
        assertEquals(1, captor.getValue().getTokensRequested()); // Fiind primul request, contorul trebuie să fie 1
    }

    @Test
    void validateAndConsumeOtp_ThrowsException_IfExpired() {
        // Arrange: Creăm un token care a expirat acum 5 minute
        UserAuthToken expiredToken = new UserAuthToken();
        expiredToken.setEmail(TEST_EMAIL);
        expiredToken.setExpiresAt(Instant.now().minus(5, MINUTES));

        when(authTokenRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(expiredToken));

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> otpService.validateAndConsumeOtp(TEST_EMAIL, "123456"));

        assertEquals("Codul OTP a expirat. Te rugăm să ceri altul.", exception.getMessage());

        // Verificăm linia care o șterge din baza de date (linia 82 din screenshot-ul tău)
        verify(authTokenRepository).delete(expiredToken);
    }

    @Test
    void checkAndApplyRateLimit_Success_BlockHasExpired() {
        // Arrange: Userul a fost blocat, dar timpul a expirat acum 5 minute.
        LoginRateLimit limit = new LoginRateLimit();
        limit.setEmail(TEST_EMAIL);
        limit.setTokensRequested(5);
        limit.setBlockedUntil(Instant.now().minus(5, MINUTES)); // MAGIA: Blocarea a expirat în trecut!
        limit.setLastAttemptAt(Instant.now().minus(65, MINUTES)); // A încercat acum mai bine de o oră

        when(rateLimitRepository.findById(TEST_EMAIL)).thenReturn(Optional.of(limit));

        // Act
        assertDoesNotThrow(() -> otpService.checkAndApplyRateLimit(TEST_EMAIL));

        // Assert:
        // Deoarece au trecut și cele 20 de minute (65 min de la ultima încercare),
        // contorul trebuie să se reseteze, iar blocarea să fie ștearsă (setată pe null).
        assertEquals(1, limit.getTokensRequested());
        assertNull(limit.getBlockedUntil()); // Contul a fost deblocat cu succes
        verify(rateLimitRepository).save(limit);
    }
}