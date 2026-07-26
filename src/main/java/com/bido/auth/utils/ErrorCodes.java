package com.bido.auth.utils;

public final class ErrorCodes {
    private ErrorCodes() {}

    public static final String ROLE_MISSING        = "ROLE_MISSING";
    public static final String ROLE_ADMIN_INVALID  = "ROLE_ADMIN_INVALID";
    public static final String INVALID_OTP         = "INVALID_OTP";
    public static final String ACCOUNT_SUSPENDED   = "ACCOUNT_SUSPENDED";
    public static final String INVALID_TOKEN       = "INVALID_TOKEN";
    public static final String RATE_LIMIT_OTP      = "RATE_LIMIT_OTP";
    public static final String RATE_LIMIT_BLOCKED  = "RATE_LIMIT_BLOCKED";
    public static final String USER_NOT_FOUND      = "USER_NOT_FOUND";
    public static final String FORBIDDEN           = "FORBIDDEN";
}
