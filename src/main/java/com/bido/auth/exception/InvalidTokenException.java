package com.bido.auth.exception;

import com.bido.auth.utils.ErrorCodes;
import org.springframework.http.HttpStatus;

public class InvalidTokenException extends AppException {
    public InvalidTokenException(String message) {
        super(ErrorCodes.INVALID_TOKEN, message, HttpStatus.UNAUTHORIZED);
    }
}
