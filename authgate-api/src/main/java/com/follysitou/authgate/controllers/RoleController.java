package com.follysitou.authgate.controllers;

import com.follysitou.authgate.dtos.role.RoleRequest;
import com.follysitou.authgate.models.Role;
import com.follysitou.authgate.service.RoleService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@RestController
@RequestMapping("/api/roles")
@PreAuthorize("hasAuthority('role_manage')")
public class RoleController {

    private final RoleService roleService;

    public RoleController(RoleService roleService) {
        this.roleService = roleService;
    }

    @PostMapping
    public ResponseEntity<Role> createRole(@RequestBody RoleRequest request) {
        Role role = roleService.createRole(request.getName(), request.getPermissionIds());
        return ResponseEntity.ok(role);
    }

    @PutMapping("/{roleId}/permissions")
    public ResponseEntity<Role> updateRolePermissions(
            @PathVariable Long roleId,
            @RequestBody Set<Long> permissionIds) {
        Role role = roleService.updateRolePermissions(roleId, permissionIds);
        return ResponseEntity.ok(role);
    }
}
