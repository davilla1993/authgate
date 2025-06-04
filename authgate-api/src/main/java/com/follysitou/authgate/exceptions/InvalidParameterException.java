package com.follysitou.authgate.exceptions;

import com.follysitou.authgate.handlers.ErrorCodes;

import java.util.List;

public class InvalidParameterException extends AbstractException {

    public InvalidParameterException(String message) {
        super(message, ErrorCodes.INVALID_PARAMETER);
    }

    public InvalidParameterException(String message, Throwable cause) {
        super(message, cause, ErrorCodes.INVALID_PARAMETER);
    }

    public InvalidParameterException(String message, List<String> errors) {
        super(message, ErrorCodes.INVALID_PARAMETER, errors);
    }
}
