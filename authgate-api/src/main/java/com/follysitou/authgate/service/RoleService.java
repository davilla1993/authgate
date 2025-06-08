package com.follysitou.authgate.service;

import com.follysitou.authgate.dtos.auth.ApiResponse;
import com.follysitou.authgate.dtos.role.RoleRequest;
import com.follysitou.authgate.exceptions.BusinessException;
import com.follysitou.authgate.models.Permission;
import com.follysitou.authgate.models.Role;
import com.follysitou.authgate.models.User;
import com.follysitou.authgate.repository.PermissionRepository;
import com.follysitou.authgate.repository.RoleRepository;
import com.follysitou.authgate.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
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

    @CacheEvict(value = "roles", allEntries = true)
    public Role updateRolePermissions(Long roleId, Set<Long> permissionIds) {
        Role role = getRoleById(roleId);
        Set<Permission> permissions = permissionIds.stream()
                .map(id -> permissionRepo.findById(id)
                        .orElseThrow(() -> new EntityNotFoundException("Permission non trouvée: " + id)))
                .collect(Collectors.toSet());
        role.setPermissions(permissions);
        return roleRepo.save(role);
    }

    @CacheEvict(value = "roles", allEntries = true)
    public void deleteRole(Long roleId) {
        Role role = getRoleById(roleId);
        roleRepo.delete(role);
    }

    @Transactional
    public void createAndAssignBasicRole(User user) {
        Role basicRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new BusinessException(
                        "ROLE_USER not found - system is not properly initialized"));

        user.getRoles().add(basicRole);
    }
}
