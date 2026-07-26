package com.bido.auth.controller;

import com.bido.auth.dto.AdminUserListDto;
import com.bido.auth.security.AuthContext;
import com.bido.auth.service.AdminService;
import com.bido.auth.service.SuspensionService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/auth/admin")
public class AdminController {

    private final AdminService adminService;
    private final SuspensionService suspensionService;

    public AdminController(AdminService adminService, SuspensionService suspensionService) {
        this.adminService = adminService;
        this.suspensionService = suspensionService;
    }

    @GetMapping("/users")
    public ResponseEntity<List<AdminUserListDto>> listUsers(AuthContext auth) {
        auth.requireAdmin();
        return ResponseEntity.ok(adminService.listManagedUsers());
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
