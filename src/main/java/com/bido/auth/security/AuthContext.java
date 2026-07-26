package com.bido.auth.security;

import com.bido.auth.entity.enums.UserRole;
import com.bido.auth.exception.ForbiddenException;
import com.bido.auth.utils.ErrorMessages;


public record AuthContext(Long userId, String role, String email) {

    public void requireAdmin() {
        if (!UserRole.ADMIN.name().equals(role)) {
            throw new ForbiddenException(ErrorMessages.ADMIN_ONLY);
        }
    }
}
