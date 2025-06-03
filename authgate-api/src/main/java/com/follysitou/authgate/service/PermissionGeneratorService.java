package com.follysitou.authgate.service;

import com.follysitou.authgate.models.Permission;
import com.follysitou.authgate.models.enums.PermissionTemplate;
import com.follysitou.authgate.repository.PermissionRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Service
@Transactional
@RequiredArgsConstructor
public class PermissionGeneratorService {


    private final PermissionRepository permissionRepository;

    public void initPermissions() {
        Arrays.stream(PermissionTemplate.values())
                .forEach(this::createPermissionIfMissing);
    }

    private void createPermissionIfMissing(PermissionTemplate template) {
        if (!permissionRepository.existsByNameIgnoreCase(template.getPermission())) {
            Permission p = new Permission();
            p.setName(template.getPermission());
            p.setDescription("Auto-generated: " + template.name());
            permissionRepository.save(p);
        }
    }
}
