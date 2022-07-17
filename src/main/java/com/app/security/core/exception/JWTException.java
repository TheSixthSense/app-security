package com.app.security.core.exception;

import com.app.security.core.constants.ErrorCode;
import lombok.Getter;

@Getter
public class JWTException extends RuntimeException {

    private final ErrorCode errorCode;
    private final String message;

    public JWTException(final ErrorCode errorCode) {
        this.errorCode = errorCode;
        this.message = errorCode.getMessage();
    }

    public JWTException(final ErrorCode errorCode, final String message) {
        this.errorCode = errorCode;
        this.message = message;
    }
}
