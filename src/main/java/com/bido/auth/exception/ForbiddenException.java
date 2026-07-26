package com.bido.auth.exception;

import com.bido.auth.utils.ErrorCodes;
import org.springframework.http.HttpStatus;

public class ForbiddenException extends AppException {
    public ForbiddenException(String message) {
        super(ErrorCodes.FORBIDDEN, message, HttpStatus.FORBIDDEN);
    }
}
