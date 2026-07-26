package com.bido.auth.controller;

import com.bido.auth.security.AuthContext;
import com.bido.auth.service.SuspensionService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth/admin")
public class AdminController {

    private final SuspensionService suspensionService;

    public AdminController(SuspensionService suspensionService) {
        this.suspensionService = suspensionService;
    }

    /**
     * Confirmă că apelantul chiar e admin: 200 pentru ADMIN, 403 altfel
     * (401 dacă gateway-ul respinge tokenul). Frontend-ul îl folosește ca
     * verificare autoritativă — el nu poate valida semnătura JWT.
     */
    @GetMapping("/me")
    public ResponseEntity<Void> me(AuthContext auth) {
        auth.requireAdmin();
        return ResponseEntity.ok().build();
    }

    @PostMapping("/users/{userId}/suspend")
    public ResponseEntity<Void> suspend(@PathVariable Long userId, AuthContext auth) {
        auth.requireAdmin();
        suspensionService.suspend(userId);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/users/{userId}/unsuspend")
    public ResponseEntity<Void> unsuspend(@PathVariable Long userId, AuthContext auth) {
        auth.requireAdmin();
        suspensionService.unsuspend(userId);
        return ResponseEntity.ok().build();
    }
}
