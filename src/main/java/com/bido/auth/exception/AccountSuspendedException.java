package com.bido.auth.exception;

import com.bido.auth.utils.ErrorCodes;
import org.springframework.http.HttpStatus;

public class AccountSuspendedException extends AppException {
    public AccountSuspendedException(String message) {
        super(ErrorCodes.ACCOUNT_SUSPENDED, message, HttpStatus.FORBIDDEN);
    }
}
