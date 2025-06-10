package com.follysitou.authgate.exceptions;

import com.follysitou.authgate.handlers.ErrorCodes;

public class AccountDisableException extends AbstractException {

    public AccountDisableException(String message) {
        super(message, ErrorCodes.ACCOUNT_DISABLED);
    }

    public AccountDisableException(String message, Throwable cause) {
        super(message, cause, ErrorCodes.ACCOUNT_DISABLED);
    }
}
