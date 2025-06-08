package com.follysitou.authgate.exceptions;

import com.follysitou.authgate.handlers.ErrorCodes;

import java.util.List;

public class EmailSendingException extends AbstractException {

    public EmailSendingException(String message, Throwable cause) {
        super(message, cause, ErrorCodes.EXTERNAL_SERVICE_ERROR);
    }
}
