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
