package com.bido.auth.security;

import com.bido.auth.entity.enums.UserRole;
import com.bido.auth.exception.ForbiddenException;
import com.bido.auth.utils.ErrorMessages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public record AuthContext(Long userId, String role, String email) {

    private static final Logger log = LoggerFactory.getLogger(AuthContext.class);

    public void requireAdmin() {
        if (!UserRole.ADMIN.name().equals(role)) {
            log.warn("Securitate - Acces refuzat pentru user cu id = {} si role = {} care a incercat sa acceseze o resursa de admin", userId, role);
            throw new ForbiddenException(ErrorMessages.ADMIN_ONLY);
        }
    }
}
