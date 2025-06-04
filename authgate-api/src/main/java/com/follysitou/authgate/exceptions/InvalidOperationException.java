package com.follysitou.authgate.exceptions;

import com.follysitou.authgate.handlers.ErrorCodes;

import java.util.List;

public class InvalidOperationException extends AbstractException {

    public InvalidOperationException(String message) {
        super(message, ErrorCodes.INVALID_OPERATION);
    }

    public InvalidOperationException(String message, Throwable cause) {
        super(message, cause, ErrorCodes.INVALID_OPERATION);
    }

    public InvalidOperationException(String message, ErrorCodes errorCode) {
        super(message, errorCode);
    }

    public InvalidOperationException(String message, ErrorCodes errorCode, List<String> errors) {
        super(message, errorCode, errors);
    }
}
