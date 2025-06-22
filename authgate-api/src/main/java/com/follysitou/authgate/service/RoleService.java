package com.follysitou.authgate.service;

import com.follysitou.authgate.dtos.role.RoleRequest;
import com.follysitou.authgate.exceptions.BusinessException;
import com.follysitou.authgate.exceptions.EntityNotFoundException;
import com.follysitou.authgate.exceptions.InvalidOperationException;
import com.follysitou.authgate.models.Permission;
import com.follysitou.authgate.models.Role;
import com.follysitou.authgate.models.User;
import com.follysitou.authgate.repository.PermissionRepository;
import com.follysitou.authgate.repository.RoleRepository;
import com.follysitou.authgate.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class RoleService {

    private final RoleRepository roleRepo;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepo;

    @Cacheable("roles")
    public List<Role> getAllRoles() {
        return roleRepo.findAll();
    }

    @Cacheable("roles")
    public Role getRoleById(Long id) {
        return roleRepo.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Role not found with ID: " + id));
    }

    @CacheEvict(value = "roles", allEntries = true)
    public Role createRole(String name, Set<Long> permissionIds) {
        Role role = new Role();
        role.setName(name);

        Set<Permission> permissions = permissionIds.stream()
                .map(id -> permissionRepo.findById(id).orElseThrow())
                .collect(Collectors.toSet());

        role.setPermissions(permissions);
        return roleRepo.save(role);
    }

    @CacheEvict(value = "roles", allEntries = true)
    public Role updateRole(Long roleId, RoleRequest request) {
        Role role = getRoleById(roleId);
        role.setName(request.getName());
        return updateRolePermissions(roleId, request.getPermissionIds());
    }

    @Transactional
    @CacheEvict(value = "userPermissions", key = "#userId")
    public void updateUserRole(Long userId, Set<Long> roleIds) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found with ID: " + userId));

        Set<Role> roles = roleIds.stream()
                .map(this::getRoleById)
                .collect(Collectors.toSet());

        user.setRoles(roles);

        userRepository.save(user);
    }
    
    @CacheEvict(value = "roles", allEntries = true)
    public Role updateRolePermissions(Long roleId, Set<Long> permissionIds) {
        Role role = getRoleById(roleId);
        Set<Permission> existingPermissions = role.getPermissions();

        Set<Permission> newPermissions = permissionIds.stream()
                .map(id -> permissionRepo.findById(id)
                        .orElseThrow(() -> new EntityNotFoundException("Permission not found: " + id)))
                .collect(Collectors.toSet());
        existingPermissions.addAll(newPermissions);
        role.setPermissions(existingPermissions);

        return roleRepo.save(role);
    }

    @CacheEvict(value = "roles", allEntries = true)
    public void deleteRole(Long roleId) {
        Role role = roleRepo.findById(roleId)
                .orElseThrow(() -> new EntityNotFoundException("Role not found"));

        // Vérifier si le rôle est attribué à des utilisateurs
        boolean roleAttribue = userRepository.existsByRolesContaining(role);
        if (roleAttribue) {
            throw new InvalidOperationException("Unable to delete this role because it is still assigned to users");
        }

        // Vérifier si le rôle contient encore des permissions
        if (!role.getPermissions().isEmpty()) {
            throw new InvalidOperationException("Cannot delete this role because it still contains permissions");
        }

        roleRepo.delete(role);
    }

    @Transactional
    public void createAndAssignBasicRole(User user) {
        Role basicRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new BusinessException(
                        "ROLE_USER not found - system is not properly initialized"));

        user.getRoles().add(basicRole);
    }

    public void revokeRoleFromUser(Long userId, Long roleId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        Role roleToRemove = roleRepo.findById(roleId)
                .orElseThrow(() -> new EntityNotFoundException("Role not found"));

        if (!user.getRoles().contains(roleToRemove)) {
            throw new BusinessException("User does not have this role assigned");
        }

        user.getRoles().remove(roleToRemove);
        userRepository.save(user);
    }

    public void removePermissionsFromRole(Long roleId, Set<Long> permissionIds) {
        Role role = getRoleById(roleId);

        Set<Permission> permissionsToRemove = permissionIds.stream()
                .map(id -> permissionRepo.findById(id)
                        .orElseThrow(() -> new EntityNotFoundException("Permission not found: " + id)))
                .collect(Collectors.toSet());

        role.getPermissions().removeAll(permissionsToRemove);
        roleRepo.save(role);
    }

}
