package com.follysitou.authgate.exceptions;

import com.follysitou.authgate.handlers.ErrorCodes;

import java.util.List;

public class UnauthorizedException extends AbstractException {

    public UnauthorizedException(String message) {
        super(message, ErrorCodes.UNAUTHORIZED_ACCESS);
    }

    public UnauthorizedException(String message, Throwable cause) {
        super(message, cause, ErrorCodes.UNAUTHORIZED_ACCESS);
    }

    public UnauthorizedException(String message, ErrorCodes errorCode) {
        super(message, errorCode);
    }

    public UnauthorizedException(String message, ErrorCodes errorCode, List<String> errors) {
        super(message, errorCode, errors);
    }
}
