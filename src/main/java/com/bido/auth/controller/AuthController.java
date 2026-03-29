package com.bido.auth.controller;

import com.bido.auth.dto.AuthResponse;
import com.bido.auth.dto.RefreshTokenRequest;
import com.bido.auth.dto.VerifyOtpRequest;
import com.bido.auth.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // Endpoint 1: Frontend-ul cere trimiterea unui cod pe email
    @PostMapping("/request-otp")
    public ResponseEntity<String> requestOtp(@RequestParam String email) {
        authService.requestOtp(email);
        return ResponseEntity.ok("Dacă adresa este validă, un cod OTP a fost trimis.");
    }

    // Endpoint 2: Frontend-ul trimite codul pentru validare
    @PostMapping("/verify-otp")
    public ResponseEntity<AuthResponse> verifyOtp(@RequestBody VerifyOtpRequest request) {
        AuthResponse response = authService.verifyOtp(request.email(), request.otpCode());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponse> refreshToken(@RequestBody RefreshTokenRequest request) {
        AuthResponse response = authService.refreshToken(request.refreshToken());
        return ResponseEntity.ok(response);
    }
}