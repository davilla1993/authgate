package com.follysitou.authgate.service;

import com.follysitou.authgate.models.Permission;
import com.follysitou.authgate.models.Role;
import com.follysitou.authgate.repository.PermissionRepository;
import com.follysitou.authgate.repository.RoleRepository;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Service
public class RoleService {

    private final RoleRepository roleRepo;

    private final PermissionRepository permissionRepo;

    public RoleService(RoleRepository roleRepo, PermissionRepository permissionRepo) {
        this.roleRepo = roleRepo;
        this.permissionRepo = permissionRepo;
    }

    public Role createRole(String name, Set<Long> permissionIds) {
        Role role = new Role();
        role.setName(name);

        Set<Permission> permissions = permissionIds.stream()
                .map(id -> permissionRepo.findById(id).orElseThrow())
                .collect(Collectors.toSet());

        role.setPermissions(permissions);
        return roleRepo.save(role);
    }

    public Role updateRolePermissions(Long roleId, Set<Long> permissionIds) {
        Role role = roleRepo.findById(roleId)
                .orElseThrow(() -> new EntityNotFoundException("Role non trouvé : " + roleId));

        Set<Permission> permissions = permissionIds.stream()
                .map(id -> permissionRepo.findById(id)
                        .orElseThrow(() -> new EntityNotFoundException("Permission non trouvée : " + id)))
                .collect(Collectors.toSet());

        role.setPermissions(permissions);
        return roleRepo.save(role);
    }
}
