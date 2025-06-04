package com.follysitou.authgate.exceptions;

import com.follysitou.authgate.handlers.ErrorCodes;
import lombok.Getter;
import java.util.Collections;
import java.util.List;

@Getter
public abstract class AbstractException extends RuntimeException {

    private ErrorCodes errorCode;
    private final List<String> errors;

    public AbstractException(String message) {
        super(message);
        this.errors = Collections.singletonList(message);
    }

    public AbstractException(String message, Throwable cause) {
        super(message, cause);
        this.errors = Collections.singletonList(message);
    }

    public AbstractException(String message, ErrorCodes errorCode) {
        super(message);
        this.errorCode = errorCode;
        this.errors = Collections.singletonList(message);
    }

    public AbstractException(String message, Throwable cause, ErrorCodes errorCode) {
        super(message, cause);
        this.errorCode = errorCode;
        this.errors = Collections.singletonList(message);
    }

    public AbstractException(String message, ErrorCodes errorCode, List<String> errors) {
        super(message);
        this.errorCode = errorCode;
        this.errors = errors;
    }

    public AbstractException(String message, Throwable cause, ErrorCodes errorCode, List<String> errors) {
        super(message, cause);
        this.errorCode = errorCode;
        this.errors = errors;
    }
}
