package com.bido.auth.dto;

import com.bido.auth.entity.enums.UserRole;

import java.time.Instant;

/** Un user așa cum îl vede panoul de admin. */
public record AdminUserListDto(
        Long id,
        String email,
        UserRole role,
        boolean suspended,
        Instant createdAt,
        Instant lastLoginAt
) {}
