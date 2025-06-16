package com.follysitou.authgate.service;

import lombok.Builder;

import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;


public class DynamicPermissionGenerator {

    public static Map<String, String> generatePermissionMapFor( Class<?> entityClass,
                                                                String rolePrefix,
                                                                String labelFrançais) {

        String resource = entityClass.getSimpleName().toLowerCase();
        return Arrays.stream(PermissionAction.values())
                .collect(Collectors.toMap(
                        action -> formatPermission(rolePrefix, resource, action.name()),
                        action -> labelFrançais + " - " + action.name().toLowerCase()
                ));
    }

    public static String formatPermission(String role, String resource, String action) {
        return role + ":" + resource + ":" + action.toLowerCase(); // pour annotation @PreAuthorize
    }

    public static String toDatabaseFormat(String permission) {
        return permission.replace(":", "_").toUpperCase(); // pour enregistrement en base
    }

    public enum PermissionAction {
        create, read, update, delete,
        lock, unlock, assign, export,
        upload_photo, delete_photo,
        view_photo
    }
}



