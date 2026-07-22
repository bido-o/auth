package com.bido.auth.exception;

import org.springframework.http.HttpStatus;

public class InvalidRoleException extends AppException {
    public InvalidRoleException(String code, String message) {
        super(code, message, HttpStatus.BAD_REQUEST);
    }
}
