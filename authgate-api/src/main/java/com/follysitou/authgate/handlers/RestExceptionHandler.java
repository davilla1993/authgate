package com.follysitou.authgate.handlers;

import com.follysitou.authgate.exceptions.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@RestControllerAdvice
@Slf4j
public class RestExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorDto> handleGenericException(Exception ex, WebRequest webRequest) {
        log.error("An unexpected error occurred: {}", ex.getMessage(), ex);
        final HttpStatus internalServerError = HttpStatus.INTERNAL_SERVER_ERROR;
        final ErrorDto errorDto = ErrorDto.builder()
                .code(ErrorCodes.UNKNOWN_ERROR)
                .httpCode(internalServerError.value())
                .message("Une erreur inattendue est survenue. Veuillez réessayer plus tard.")
                .errors(Collections.singletonList(ex.getMessage()))
                .build();
        return new ResponseEntity<>(errorDto, internalServerError);
    }

    // Gérer les exceptions personnalisées
    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<ErrorDto> handleEntityNotFoundException(EntityNotFoundException exception, WebRequest webRequest){
        log.warn("EntityNotFoundException: {}", exception.getMessage());
        final HttpStatus notFound = HttpStatus.NOT_FOUND; // Statut 404
        final ErrorDto errorDto = ErrorDto.builder()
                .code(exception.getErrorCode())
                .httpCode(notFound.value())
                .message(exception.getMessage())
                .errors(exception.getErrors())
                .build();
        return new ResponseEntity<>(errorDto, notFound);
    }

    @ExceptionHandler(InvalidOperationException.class)
    public ResponseEntity<ErrorDto> handleInvalidOperationException(InvalidOperationException exception, WebRequest webRequest){
        log.warn("InvalidOperationException: {}", exception.getMessage());
        final HttpStatus badRequest = HttpStatus.BAD_REQUEST; // Statut 400
        final ErrorDto errorDto = ErrorDto.builder()
                .code(exception.getErrorCode())
                .httpCode(badRequest.value())
                .message(exception.getMessage())
                .errors(exception.getErrors())
                .build();
        return new ResponseEntity<>(errorDto, badRequest);
    }

    @ExceptionHandler(InvalidParameterException.class)
    public ResponseEntity<ErrorDto> handleInvalidParameterException(InvalidParameterException exception, WebRequest webRequest){
        log.warn("InvalidParameterException: {}", exception.getMessage());
        final HttpStatus badRequest = HttpStatus.BAD_REQUEST; // Statut 400
        final ErrorDto errorDto = ErrorDto.builder()
                .code(exception.getErrorCode())
                .httpCode(badRequest.value())
                .message(exception.getMessage())
                .errors(exception.getErrors())
                .build();
        return new ResponseEntity<>(errorDto, badRequest);
    }

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<ErrorDto> handleUnauthorizedException(UnauthorizedException exception, WebRequest webRequest){
        log.warn("UnauthorizedException: {}", exception.getMessage());
        final HttpStatus unauthorized = HttpStatus.UNAUTHORIZED; // Statut 401
        final ErrorDto errorDto = ErrorDto.builder()
                .code(exception.getErrorCode())
                .httpCode(unauthorized.value())
                .message(exception.getMessage())
                .errors(exception.getErrors())
                .build();
        return new ResponseEntity<>(errorDto, unauthorized);
    }

    @ExceptionHandler(ForbiddenException.class)
    public ResponseEntity<ErrorDto> handleForbiddenException(ForbiddenException exception, WebRequest webRequest){
        log.warn("ForbiddenException: {}", exception.getMessage());
        final HttpStatus forbidden = HttpStatus.FORBIDDEN; // Statut 403
        final ErrorDto errorDto = ErrorDto.builder()
                .code(exception.getErrorCode())
                .httpCode(forbidden.value())
                .message(exception.getMessage())
                .errors(exception.getErrors())
                .build();
        return new ResponseEntity<>(errorDto, forbidden);
    }

    @ExceptionHandler(ResourceAlreadyExistsException.class)
    public ResponseEntity<ErrorDto> handleResourceAlreadyExists(ResourceAlreadyExistsException exception, WebRequest webRequest){
        log.warn("ResourceAlreadyExists: {}", exception.getMessage());
        final HttpStatus conflict = HttpStatus.CONFLICT;
        final ErrorDto errorDto = ErrorDto.builder()
                .code(exception.getErrorCode())
                .httpCode(conflict.value())
                .message(exception.getMessage())
                .errors(exception.getErrors())
                .build();
        return new ResponseEntity<>(errorDto, conflict);
    }

    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ErrorDto> handleBusinessException(BusinessException exception, WebRequest webRequest){
        log.warn("BusinessException: {}", exception.getMessage());
        final HttpStatus conflict = HttpStatus.CONFLICT; // Statut 409 (souvent utilisé pour les règles métier)
        final ErrorDto errorDto = ErrorDto.builder()
                .code(exception.getErrorCode())
                .httpCode(conflict.value())
                .message(exception.getMessage())
                .errors(exception.getErrors())
                .build();
        return new ResponseEntity<>(errorDto, conflict);
    }

    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<ErrorDto> handleValidationException(ValidationException exception, WebRequest webRequest){
        log.warn("ValidationException: {}", exception.getMessage());
        final HttpStatus badRequest = HttpStatus.BAD_REQUEST; // Statut 400
        final ErrorDto errorDto = ErrorDto.builder()
                .code(exception.getErrorCode())
                .httpCode(badRequest.value())
                .message(exception.getMessage())
                .errors(exception.getErrors())
                .build();
        return new ResponseEntity<>(errorDto, badRequest);
    }

    // Garder la gestion de BadCredentialsException car c'est une exception Spring Security spécifique
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorDto> handleBadCredentialsException(BadCredentialsException exception, WebRequest webRequest){
        log.warn("BadCredentialsException: {}", exception.getMessage());
        final HttpStatus badRequest = HttpStatus.BAD_REQUEST;
        final ErrorDto errorDto = ErrorDto.builder()
                .code(ErrorCodes.BAD_CREDENTIALS)
                .httpCode(badRequest.value())
                .message("Login et/ou mot de passe incorrects")
                .errors(Collections.singletonList("Login et/ou mot de passe incorrects"))
                .build();
        return new ResponseEntity<>(errorDto, badRequest);
    }

    // Gérer les erreurs de validation de Spring (@Valid, @RequestBody)
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
                                                                  org.springframework.http.HttpHeaders headers,
                                                                  HttpStatus status, WebRequest request) {
        log.warn("MethodArgumentNotValidException: {}", ex.getMessage());
        List<String> errors = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.toList());

        final ErrorDto errorDto = ErrorDto.builder()
                .code(ErrorCodes.VALIDATION_ERROR)
                .httpCode(status.value())
                .message("Erreurs de validation des données.")
                .errors(errors)
                .build();

        return new ResponseEntity<>(errorDto, status);
    }
}
