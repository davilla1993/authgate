package com.follysitou.authgate.exceptions;

import com.follysitou.authgate.handlers.ErrorCodes;

import java.util.List;

public class BusinessException extends AbstractException {

    public BusinessException(String message) {
        super(message, ErrorCodes.BUSINESS_RULE_VIOLATION);
    }

    public BusinessException(String message, Throwable cause) {
        super(message, cause, ErrorCodes.BUSINESS_RULE_VIOLATION);
    }

    public BusinessException(String message, List<String> errors) {
        super(message, ErrorCodes.BUSINESS_RULE_VIOLATION, errors);
    }
}
