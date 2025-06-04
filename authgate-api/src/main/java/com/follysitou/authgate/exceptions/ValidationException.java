package com.follysitou.authgate.exceptions;

import com.follysitou.authgate.handlers.ErrorCodes;

import java.util.List;

public class ValidationException extends AbstractException {

    public ValidationException(String message) {
        super(message, ErrorCodes.VALIDATION_ERROR);
    }

    public ValidationException(String message, List<String> errors) {
        super(message, ErrorCodes.VALIDATION_ERROR, errors);
    }
}