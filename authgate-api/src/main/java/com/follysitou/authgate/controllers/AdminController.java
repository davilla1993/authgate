package com.follysitou.authgate.controllers;


import com.follysitou.authgate.dtos.auth.ApiResponse;
import com.follysitou.authgate.dtos.auth.LockAccountRequest;
import com.follysitou.authgate.dtos.role.RoleRequest;
import com.follysitou.authgate.dtos.user.UserResponseDto;
import com.follysitou.authgate.mappers.user.UserMapper;
import com.follysitou.authgate.models.BlackListedToken;
import com.follysitou.authgate.models.Role;
import com.follysitou.authgate.models.User;
import com.follysitou.authgate.repository.BlackListedTokenRepository;
import com.follysitou.authgate.repository.UserRepository;
import com.follysitou.authgate.service.AuthService;
import com.follysitou.authgate.service.JwtService;
import com.follysitou.authgate.service.RoleService;
import com.follysitou.authgate.service.UserService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final UserService userService;
    private final AuthService authService;
    private final RoleService roleService;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final BlackListedTokenRepository blackListedTokenRepository;


    // User Management Endpoints
  //  @PreAuthorize("(hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')) and hasAuthority('account_status:view')")

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('user:read')")
    public ResponseEntity<Page<UserResponseDto>> getAllUsers(
            @RequestParam(required = false) Boolean active,
            @RequestParam(required = false) String search,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        return ResponseEntity.ok(userService.getAllUsers(active, search, pageable));
    }

    @GetMapping("/users/online")
    @PreAuthorize("hasAuthority('user:read')")
    public ResponseEntity<List<UserResponseDto>> getOnlineUsers() {
        return ResponseEntity.ok(userService.getOnlineUsers());
    }

    @GetMapping("/users/locked")
    @PreAuthorize("hasAuthority('user:read')")
    public ResponseEntity<List<UserResponseDto>> getLockedAccounts() {
        List<User> lockedUsers = userRepository.findAllLockedAccounts();
        return ResponseEntity.ok(lockedUsers.stream()
                .map(UserMapper::mapToDto)
                .collect(Collectors.toList()));
    }

    @PutMapping("/users/{id}")
    @PreAuthorize("hasAuthority('user:update')")
    public ResponseEntity<UserResponseDto> updateUser(
            @PathVariable Long id,
            @RequestBody Map<String, Object> updates,
            @AuthenticationPrincipal UserDetails admin) {
        UserResponseDto updated = userService.updateUser(id, updates, admin.getUsername());
        return ResponseEntity.ok(updated);
    }

    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasAuthority('user:delete')")
    public ResponseEntity<?> deleteUser(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails admin) {
        userService.deleteUser(id, admin.getUsername());
        return ResponseEntity.ok(new ApiResponse(true, "Utilisateur supprimé"));
    }

    @PutMapping("/users/{id}/disable")
    @PreAuthorize("hasAuthority('user:lock')")
    public ResponseEntity<?> disableUser(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails admin) {
        userService.disableUser(id, admin.getUsername());
        return ResponseEntity.ok(new ApiResponse(true, "Utilisateur désactivé"));
    }

    @PutMapping("/users/{id}/enable")
    @PreAuthorize("hasAuthority('user:unlock')")
    public ResponseEntity<?> enableUser(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails admin) {
        userService.enableUser(id, admin.getUsername());
        return ResponseEntity.ok(new ApiResponse(true, "Utilisateur activé"));
    }

    @PutMapping("/users/{id}/reset-password")
    @PreAuthorize("hasAuthority('user:update')")
    public ResponseEntity<?> resetPasswordByAdmin(
            @PathVariable Long id,
            @RequestParam String newPassword,
            @AuthenticationPrincipal UserDetails admin) {
        userService.resetPassword(id, newPassword, admin.getUsername());
        return ResponseEntity.ok(new ApiResponse(true, "Mot de passe réinitialisé"));
    }

    @PostMapping("/users/lock")
    @PreAuthorize("hasAuthority('user:lock')")
    public ResponseEntity<?> lockUserAccount(
            @Valid @RequestBody LockAccountRequest request,
            @AuthenticationPrincipal UserDetails admin) {
        ApiResponse response = authService.lockUserAccount(
                request.getEmail(),
                request.getReason(),
                admin.getUsername());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/users/unlock")
    @PreAuthorize("hasAuthority('user:unlock')")
    public ResponseEntity<?> unlockUserAccount(
            @RequestParam String email) {
        ApiResponse response = authService.unlockUserAccount(email);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/users/{email}/status")
    @PreAuthorize("hasAuthority('user:read')")
    public ResponseEntity<?> getAccountStatus(@PathVariable @Email String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));

        Map<String, Object> response = new HashMap<>();
        response.put("email", user.getEmail());
        response.put("isLocked", !user.isAccountNonLocked());
        response.put("status", user.isAccountNonLocked() ? "ACTIF" : "VERROUILLÉ");
        response.put("lastLoginAttempt", user.getLastLoginAttempt());
        response.put("passwordChangedAt", user.getPasswordChangedAt());

        if (!user.isAccountNonLocked()) {
            response.put("lockReason", user.getLockReason());
            response.put("lockedSince", user.getManualLockTime());
            response.put("lockedBy", user.getLockedBy());
        }

        response.put("failedAttempts", user.getFailedAttempts());
        response.put("lastUpdate", user.getUpdatedAt());

        if (user.getPasswordChangedAt() != null) {
            long passwordAgeDays = ChronoUnit.DAYS.between(
                    user.getPasswordChangedAt(),
                    LocalDateTime.now());
            response.put("passwordAgeDays", passwordAgeDays);
        }

        return ResponseEntity.ok(response);
    }

    // Role Management Endpoints

    @PostMapping("/roles")
    @PreAuthorize("hasAuthority('role:create')")
    public ResponseEntity<Role> createRole(@RequestBody RoleRequest request) {
        Role role = roleService.createRole(request.getName(), request.getPermissionIds());
        return ResponseEntity.ok(role);
    }

    @PutMapping("/roles/{roleId}/permissions")
    @PreAuthorize("hasAuthority('role:update')")
    public ResponseEntity<Role> updateRolePermissions(
            @PathVariable Long roleId,
            @RequestBody Set<Long> permissionIds) {
        Role role = roleService.updateRolePermissions(roleId, permissionIds);
        return ResponseEntity.ok(role);
    }

    @PostMapping("/roles/assign")
    @PreAuthorize("hasAuthority('role:assign')")
    public ResponseEntity<?> assignRoleToUser(
            @RequestParam Long userId,
            @RequestParam Long roleId) {
        // Implémentation à ajouter dans RoleService
        return ResponseEntity.ok(new ApiResponse(true, "Rôle assigné avec succès"));
    }

    // System Management Endpoints

    @GetMapping("/system/stats")
    @PreAuthorize("hasAuthority('system:read')")
    public ResponseEntity<Map<String, Object>> getSystemStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalUsers", userRepository.count());
        stats.put("activeUsers", userRepository.countByEnabledTrue());
        stats.put("lockedUsers", userRepository.countByAccountNonLockedFalse());
        stats.put("recentUsers", userRepository.countByCreatedAtAfter(LocalDateTime.now().minusDays(7)));
        return ResponseEntity.ok(stats);
    }

    @PostMapping("/tokens/revoke")
    @PreAuthorize("hasAuthority('token:revoke')")
    public ResponseEntity<ApiResponse> revokeToken(@RequestBody String token) {
        if (!jwtService.isTokenValid(token)) {
            return ResponseEntity.badRequest().body(new ApiResponse(false, "Token invalide"));
        }

        Instant expiry = jwtService.extractExpiration(token).toInstant();
        blackListedTokenRepository.save(new BlackListedToken(token, expiry));

        return ResponseEntity.ok(new ApiResponse(true, "Token révoqué avec succès"));
    }
}
