package com.follysitou.authgate.exceptions;

import com.follysitou.authgate.handlers.ErrorCodes;

import java.util.List;

public class ForbiddenException extends AbstractException {

    public ForbiddenException(String message) {
        super(message, ErrorCodes.FORBIDDEN_ACCESS);
    }

    public ForbiddenException(String message, Throwable cause) {
        super(message, cause, ErrorCodes.FORBIDDEN_ACCESS);
    }

    public ForbiddenException(String message, List<String> errors) {
        super(message, ErrorCodes.FORBIDDEN_ACCESS, errors);
    }
}
