package com.bido.auth.utils;

public final class ErrorMessages {
    private ErrorMessages() {}

    public static final String OTP_EXPIRED = "Codul OTP a expirat. Te rugăm să ceri altul.";
    public static final String OTP_NOT_REQUESTED = "Nu a fost cerut niciun cod pentru acest email!";
    public static final String OTP_MAX_ATTEMPTS = "Ai depășit limita de încercări. Poți cere alt cod.";
    public static final String OTP_INCORRECT = "Cod OTP incorect! Mai ai %d încercări.";
    public static final String ROLE_MISSING = "Contul nu există. Te rugăm să selectezi un rol pentru înregistrare.";
    public static final String ROLE_ADMIN_INVALID = "Rolul de Administrator nu poate fi ales la înregistrare.";
    public static final String ACCOUNT_SUSPENDED = "Acest cont este suspendat!";
    public static final String RATE_LIMIT_TOKENS = "Ai cerut prea multe coduri OTP. Te rugăm să încerci din nou peste o oră.";
    public static final String RATE_LIMIT_BLOCKED = "Prea multe încercări. Cont blocat temporar pentru încă %d minute.";
    public static final String TOKEN_REFRESH_INVALID = "Refresh Token invalid sau inexistent!";
    public static final String TOKEN_EXPIRED = "Sesiunea a expirat. Te rugăm să te loghezi din nou.";
}

