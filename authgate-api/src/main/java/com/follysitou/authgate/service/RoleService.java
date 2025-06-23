package com.follysitou.authgate.service;

import com.follysitou.authgate.dtos.role.RoleRequest;
import com.follysitou.authgate.exceptions.BusinessException;
import com.follysitou.authgate.exceptions.EntityNotFoundException;
import com.follysitou.authgate.exceptions.InvalidOperationException;
import com.follysitou.authgate.handlers.ErrorCodes;
import com.follysitou.authgate.models.Permission;
import com.follysitou.authgate.models.Role;
import com.follysitou.authgate.models.User;
import com.follysitou.authgate.repository.PermissionRepository;
import com.follysitou.authgate.repository.RoleRepository;
import com.follysitou.authgate.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class RoleService {

    private final RoleRepository roleRepo;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepo;
    private final RoleHierarchyService roleHierarchyService;

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
        return addPermissionsToRole(roleId, request.getPermissionIds());
    }

    @CacheEvict(value = "roles", allEntries = true)
    public Role addPermissionsToRole(Long roleId, Set<Long> permissionIds) {
        Role targetRole = getRoleById(roleId);
        Set<Permission> existingPermissions = targetRole.getPermissions();

        boolean isTargetAdminRole = targetRole.getName().equals("ROLE_ADMIN");
        roleHierarchyService.checkAccountManagerAdminRestriction(isTargetAdminRole,
                "Account Managers cannot modify permissions of the ADMIN role.");

        Set<Permission> newPermissions = permissionIds.stream()
                .map(id -> permissionRepo.findById(id)
                        .orElseThrow(() -> new EntityNotFoundException("Permission not found: " + id)))
                .collect(Collectors.toSet());
        existingPermissions.addAll(newPermissions);
        targetRole.setPermissions(existingPermissions);

        return roleRepo.save(targetRole);
    }

    @Transactional
    public void removePermissionsFromRole(Long roleId, Set<Long> permissionIds) {
        Role targetRole = getRoleById(roleId);

        boolean isTargetAdminRole = targetRole.getName().equals("ROLE_ADMIN");
        roleHierarchyService.checkAccountManagerAdminRestriction(isTargetAdminRole,
                "Account Managers cannot modify permissions of the ADMIN role.");

        Set<Permission> permissionsToRemove = permissionIds.stream()
                .map(id -> permissionRepo.findById(id)
                        .orElseThrow(() -> new EntityNotFoundException("Permission not found: " + id)))
                .collect(Collectors.toSet());

        targetRole.getPermissions().removeAll(permissionsToRemove);
        roleRepo.save(targetRole);
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

    @Transactional
    @CacheEvict(value = "userPermissions", key = "#userId")
    public void addRolesToUser(Long userId, Set<Long> roleIds) {

        User targetUser = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found: "
                                            + userId, ErrorCodes.USER_NOT_FOUND));

        boolean isTargetAdmin = targetUser.getRoles().stream()
                .anyMatch(role -> role.getName().equals("ROLE_ADMIN"));

        // Vérification 1: ACCOUNT_MANAGER ne peut pas modifier les rôles d'un utilisateur ADMIN
        roleHierarchyService.checkAccountManagerAdminRestriction(isTargetAdmin,
                "Account Managers cannot modify roles of Administrator accounts.");

        Set<Role> rolesToAdd = new HashSet<>();
        boolean isAssigningAdminRole = false; // Flag pour vérifier si ROLE_ADMIN est parmi les rôles à ajouter

        for (Long roleId : roleIds) {
            Role role = roleRepository.findById(roleId) // <-- RECHERCHE DES ROLES PAR ID
                    .orElseThrow(() -> new EntityNotFoundException("Role not found with ID: "
                            + roleId, ErrorCodes.ROLE_NOT_FOUND));
            rolesToAdd.add(role);
            if (role.getName().equals("ROLE_ADMIN")) {
                isAssigningAdminRole = true;
            }
        }
        // Vérification 2: ACCOUNT_MANAGER ne peut pas assigner le rôle ADMIN à qui que ce soit
        roleHierarchyService.checkAccountManagerAdminRestriction(isAssigningAdminRole,
                "Account Managers cannot assign the ADMIN role to any user.");

        Set<Role> currentRoles = targetUser.getRoles();
        currentRoles.addAll(rolesToAdd);
        targetUser.setRoles(currentRoles);

        userRepository.save(targetUser);
        log.info("Roles {} added to user ID {}", roleIds, userId);
    }

    @Transactional
    public void revokeRoleFromUser(Long userId, Set<Long> roleIds) {
        User targetUser = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found with ID: "
                        + userId, ErrorCodes.USER_NOT_FOUND));

        boolean isTargetAdmin = targetUser.getRoles().stream()
                .anyMatch(role -> role.getName().equals("ROLE_ADMIN"));

        // Vérification 1: ACCOUNT_MANAGER ne peut pas modifier les rôles d'un utilisateur ADMIN
        roleHierarchyService.checkAccountManagerAdminRestriction(isTargetAdmin,
                "Account Managers cannot modify roles of Administrator accounts.");

        Set<Role> rolesToRemove = new HashSet<>();
        boolean isRevokingAdminRole = false; // Flag pour vérifier si ROLE_ADMIN est parmi les rôles à révoquer

        for (Long roleId : roleIds) {
            Role role = roleRepository.findById(roleId)
                    .orElseThrow(() -> new EntityNotFoundException("Role not found with ID: "
                            + roleId, ErrorCodes.ROLE_NOT_FOUND));
            rolesToRemove.add(role);
            if (role.getName().equals("ROLE_ADMIN")) {
                isRevokingAdminRole = true;
            }
        }

        // Vérification 2: ACCOUNT_MANAGER ne peut pas révoquer le rôle ADMIN de qui que ce soit
        roleHierarchyService.checkAccountManagerAdminRestriction(isRevokingAdminRole,
                "Account Managers cannot revoke the ADMIN role from any user.");

        Set<Role> currentRoles = targetUser.getRoles();
        currentRoles.removeAll(rolesToRemove);
        targetUser.setRoles(currentRoles);

        userRepository.save(targetUser);
        log.info("Roles {} revoked from user ID {}", roleIds, userId);

    }

}
