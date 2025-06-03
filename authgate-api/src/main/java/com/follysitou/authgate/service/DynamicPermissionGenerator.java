package com.follysitou.authgate.service;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class DynamicPermissionGenerator {

    public static List<PermissionTemplate> generateFor(Class<?> entityClass) {
        String resource = entityClass.getSimpleName().toLowerCase();
        return Arrays.stream(PermissionAction.values())
                .map(action -> new PermissionTemplate(resource, action))
                .collect(Collectors.toList());
    }

    public record PermissionTemplate(String resource, PermissionAction action) {
        public String toPermissionString() {
            return resource + ":" + action.name().toLowerCase();
        }
    }

    public enum PermissionAction {
        CREATE, READ, UPDATE, DELETE,
        LOCK, UNLOCK, ASSIGN, EXPORT,
        UPLOAD_PHOTO, DELETE_PHOTO,
        VIEW_PHOTO
    }
}

