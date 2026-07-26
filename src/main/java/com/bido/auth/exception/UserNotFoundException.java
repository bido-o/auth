package com.bido.auth.exception;

import com.bido.auth.utils.ErrorCodes;
import org.springframework.http.HttpStatus;

public class UserNotFoundException extends AppException {
    public UserNotFoundException(String message) {
        super(ErrorCodes.USER_NOT_FOUND, message, HttpStatus.NOT_FOUND);
    }
}
