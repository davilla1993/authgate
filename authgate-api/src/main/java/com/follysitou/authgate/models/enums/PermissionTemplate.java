package com.follysitou.authgate.models.enums;

import lombok.Getter;

@Getter
public enum PermissionTemplate {

    // Format : {ENTITY}_{ACTION}
    USER_READ("user:read"),
    USER_CREATE("user:create"),
    USER_DELETE("user:delete"),
    USER_UPDATE("user:update"),
    USER_LOCK("user:lock"),
    USER_UNLOCK("user:unlock"),

    ROLE_CREATE("role:create"),
    ROLE_ASSIGN("role:assign");

    private final String permission;

    PermissionTemplate(String permission) {
        this.permission = permission;
    }
}
