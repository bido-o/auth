package com.bido.auth.exception;

import org.springframework.http.HttpStatus;

public class RateLimitException extends AppException {
    public RateLimitException(String code, String message) {
        super(code, message, HttpStatus.TOO_MANY_REQUESTS);
    }
}
