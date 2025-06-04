package com.follysitou.authgate.exceptions;

import com.follysitou.authgate.handlers.ErrorCodes;

import java.util.List;

public class EntityNotFoundException extends AbstractException {

    public EntityNotFoundException(String message) {
        super(message, ErrorCodes.ENTITY_NOT_FOUND);
    }

    public EntityNotFoundException(String message, Throwable cause) {
        super(message, cause, ErrorCodes.ENTITY_NOT_FOUND);
    }

    public EntityNotFoundException(String message, ErrorCodes errorCode) {
        super(message, errorCode);
    }

    public EntityNotFoundException(String message, Throwable cause, ErrorCodes errorCode) {
        super(message, cause, errorCode);
    }

    public EntityNotFoundException(String message, ErrorCodes errorCode, List<String> errors) {
        super(message, errorCode, errors);
    }
}