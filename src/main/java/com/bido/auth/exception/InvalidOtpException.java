package com.bido.auth.exception;

import com.bido.auth.utils.ErrorCodes;
import org.springframework.http.HttpStatus;

public class InvalidOtpException extends AppException {
    public InvalidOtpException(String message) {
        super(ErrorCodes.INVALID_OTP, message, HttpStatus.UNAUTHORIZED);
    }
}
