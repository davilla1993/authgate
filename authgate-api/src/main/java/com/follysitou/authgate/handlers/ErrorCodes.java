package com.follysitou.authgate.handlers;

import lombok.Getter;

@Getter
public enum ErrorCodes {

    // Erreurs générales / métier
    UNKNOWN_ERROR(1000),
    BUSINESS_RULE_VIOLATION(1001),
    VALIDATION_ERROR(1002),
    INVALID_PARAMETER(1003),
    INVALID_OPERATION(1004),


    // Erreurs d'authentification et d'autorisation
    BAD_CREDENTIALS(2000), // Login et/ou mot de passe incorrects
    ACCOUNT_LOCKED(2001),
    ACCOUNT_DISABLED(2002),
    TOKEN_EXPIRED(2003),
    TOKEN_INVALID(2004),
    TOKEN_BLACKLISTED(2005),
    UNAUTHORIZED_ACCESS(2006), // Accès non authentifié
    FORBIDDEN_ACCESS(2007),    // Accès authentifié mais non autorisé (pas les bonnes permissions/rôles)
    REFRESH_TOKEN_INVALID(2008),
    USER_ALREADY_EXISTS(2009), // Lors de l'inscription
    EMAIL_ALREADY_USED(2010),

    // Erreurs de ressources
    ENTITY_NOT_FOUND(3000),
    USER_NOT_FOUND(3001),
    ROLE_NOT_FOUND(3002),
    PERMISSION_NOT_FOUND(3003),
    RESOURCE_NOT_FOUND(3004),

    // Erreurs techniques / système
    DATABASE_ERROR(4000),
    EXTERNAL_SERVICE_ERROR(4001),
    FILE_UPLOAD_FAILED(4002),
    IO_ERROR(4003);


    private final int code;

    ErrorCodes(int code) {
        this.code = code;
    }

}
