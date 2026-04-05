package com.bido.auth.dto;

import com.bido.auth.entity.enums.UserRole;

public record RequestOtpRequest(
    String email,
    UserRole role
) {}

