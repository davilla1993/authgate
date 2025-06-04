package com.follysitou.authgate.exceptions;

import com.follysitou.authgate.handlers.ErrorCodes;

import java.util.List;

public class ResourceAlreadyExistsException extends AbstractException {

    public ResourceAlreadyExistsException(String message) {
        super(message, ErrorCodes.EMAIL_ALREADY_USED);
    }

    public ResourceAlreadyExistsException(String message, Throwable cause) {
        super(message, cause, ErrorCodes.ENTITY_NOT_FOUND);
    }

    public ResourceAlreadyExistsException(String message, ErrorCodes errorCode) {
        super(message, errorCode);
    }

    public ResourceAlreadyExistsException(String message, Throwable cause, ErrorCodes errorCode) {
        super(message, cause, errorCode);
    }

    public ResourceAlreadyExistsException(String message, ErrorCodes errorCode, List<String> errors) {
        super(message, errorCode, errors);
    }
}