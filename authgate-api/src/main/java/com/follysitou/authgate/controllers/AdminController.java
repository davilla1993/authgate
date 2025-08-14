package com.follysitou.authgate.controllers;


import com.follysitou.authgate.dtos.auth.ApiResponse;
import com.follysitou.authgate.dtos.auth.LockAccountRequest;
import com.follysitou.authgate.dtos.auth.RegisterRequest;
import com.follysitou.authgate.dtos.role.RoleRequest;
import com.follysitou.authgate.dtos.user.AccountStatusResponseDto;
import com.follysitou.authgate.dtos.user.UserResponseDto;
import com.follysitou.authgate.dtos.user.UserUpdateRequest;
import com.follysitou.authgate.exceptions.EntityNotFoundException;
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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/admin")
@PreAuthorize("hasAnyRole('ADMIN','ACCOUNT_MANAGER')")
@RequiredArgsConstructor
public class AdminController {

    private final UserService userService;
    private final AuthService authService;
    private final RoleService roleService;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final BlackListedTokenRepository blackListedTokenRepository;

    //   +++++++++++++++++++++++++++++++++++++++ User Management ++++++++++++++++++++++++++++++++++++++++++++++++++++++

    @PostMapping("/users")
    @PreAuthorize("hasAuthority('admin:user:create')")
    public ResponseEntity<ApiResponse> createUserByAdmin(@RequestBody RegisterRequest registerRequest) {
            ApiResponse newUser = userService.createUserByAdmin(registerRequest);

            return ResponseEntity.ok(newUser);
    }

    @GetMapping("users/{id}")
    @PreAuthorize("hasAuthority('admin:user:read')")
    public ResponseEntity<UserResponseDto> getUserById(@PathVariable Long id) {
        UserResponseDto userDto = userService.getUserById(id);
        return ResponseEntity.ok(userDto);
    }

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('admin:user:read')")
    public ResponseEntity<Page<UserResponseDto>> getAllUsers(
            @RequestParam(required = false) Boolean active,
            @RequestParam(required = false) String search,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());

        return ResponseEntity.ok(userService.getAllUsers(active, search, pageable));
    }

    @GetMapping("/users/online")
    @PreAuthorize("hasAuthority('admin:user:read')")
    public ResponseEntity<Page<UserResponseDto>> getOnlineUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        Pageable pageable = PageRequest.of(page, size, Sort.by("lastActivity").descending());
        Page<UserResponseDto> result = userService.getOnlineUsers(pageable);
        return ResponseEntity.ok(result);
    }

    @PutMapping("/users/{id}")
    @PreAuthorize("hasAuthority('admin:user:update')")
    public ResponseEntity<UserResponseDto> updateUser(
            @PathVariable String email,
            @RequestBody UserUpdateRequest request) {

        UserResponseDto updatedUser = userService.updateUser(email, request);

        return ResponseEntity.ok(updatedUser);
    }

    //   +++++++++++++++++++++++++++++++++++++++ Accounts Management ++++++++++++++++++++++++++++++++++++++++++++++++++++++

    @GetMapping("/users/locked")
    @PreAuthorize("hasAuthority('admin:user:account-control')")
    public ResponseEntity<Page<UserResponseDto>> getLockedAccounts(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        Pageable pageable = PageRequest.of(page, size, Sort.by("lastActivity").descending());
        Page<UserResponseDto> lockedUsers = userRepository.findAllLockedAccounts(pageable);

        return ResponseEntity.ok(lockedUsers);
    }

    @GetMapping("/users/{email}/status")
    @PreAuthorize("hasAuthority('admin:user:account-control')")
    public ResponseEntity<AccountStatusResponseDto> getAccountStatus(@PathVariable @Email String email) {

        AccountStatusResponseDto response = userService.getUserAccountStatus(email);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/users/lock")
    @PreAuthorize("hasAuthority('admin:user:account-control')")
    public ResponseEntity<?> lockUserAccount( @Valid @RequestBody LockAccountRequest request,
                                                @AuthenticationPrincipal UserDetails adminEmail) {

        ApiResponse response = authService.lockUserAccount(request.getEmail(), request.getReason(),
                adminEmail.getUsername());

        return ResponseEntity.ok(response);
    }

    @PostMapping("/users/unlock")
    @PreAuthorize("hasAuthority('admin:user:account-control')")
    public ResponseEntity<ApiResponse> unlockUserAccount(
            @RequestParam String email) {
        ApiResponse response = authService.unlockUserAccount(email);
        return ResponseEntity.ok(response);
    }

    //   +++++++++++++++++++++++++++++++++++++++ Role Management ++++++++++++++++++++++++++++++++++++++++++++++++++++++
    @PostMapping("/roles")
    @PreAuthorize("hasAuthority('admin:role:create')")
    public ResponseEntity<Role> createRole(@RequestBody RoleRequest request) {
        Role role = roleService.createRole(request.getName(), request.getPermissionIds());

        return ResponseEntity.ok(role);
    }

    @GetMapping
    @PreAuthorize("hasAuthority('admin:role:read')")
    public ResponseEntity<List<Role>> getAllRoles() {
        return ResponseEntity.ok(roleService.getAllRoles());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('admin:role:read')")
    public ResponseEntity<Role> getRoleById(@PathVariable Long id) {
        return ResponseEntity.ok(roleService.getRoleById(id));
    }

    @PutMapping("/roles/{roleId}/permissions")
    @PreAuthorize("hasAuthority('admin:role:update')")
    public ResponseEntity<Role> addPermissionsToRole(@PathVariable Long roleId,
                                                      @RequestBody Set<Long> permissionIds) {

        Role role = roleService.addPermissionsToRole(roleId, permissionIds);
        return ResponseEntity.ok(role);
    }

    @PostMapping("/roles/assign")
    @PreAuthorize("hasAuthority('admin:role:assign')")
    public ResponseEntity<ApiResponse> addRolesToUser(@RequestParam Long userId, @RequestParam Set<Long> roleId) {

        roleService.addRolesToUser(userId, roleId);
        return ResponseEntity.ok(new ApiResponse(true, "Role successfully assigned"));
    }

    @DeleteMapping("/roles/revoke")
    @PreAuthorize("hasAuthority('admin:role:revoke')")
    public ResponseEntity<ApiResponse> revokeRoleFromUser(
            @RequestParam Long userId,
            @RequestParam Set<Long> roleIds) {

        roleService.revokeRoleFromUser(userId, roleIds);
        return ResponseEntity.ok(new ApiResponse(true, "Role successfully revoked"));
    }

    @DeleteMapping("/roles/{roleId}/permissions")
    @PreAuthorize("hasAuthority('admin:role:update')")
    public ResponseEntity<ApiResponse> removePermissionsFromRole(
            @PathVariable Long roleId,
            @RequestBody Set<Long> permissionIds) {

        roleService.removePermissionsFromRole(roleId, permissionIds);
        return ResponseEntity.ok(new ApiResponse(true,
                "Permissions successfully removed from role"));
    }

    @DeleteMapping("/{roleId}")
    @PreAuthorize("hasAuthority('admin:role:delete')")
    public ResponseEntity<ApiResponse> deleteRole(@PathVariable Long roleId) {
        roleService.deleteRole(roleId);

        return ResponseEntity.ok(new ApiResponse(true, "Role deleted successfully"));
    }

    //   +++++++++++++++++++++++++++++++++++++++ System Management ++++++++++++++++++++++++++++++++++++++++++++++++++++++
    @GetMapping("/system/stats")
    @PreAuthorize("hasAuthority('admin:system:read')")
    public ResponseEntity<Map<String, Object>> getSystemStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalUsers", userRepository.count());
        stats.put("activeUsers", userRepository.countByEnabledTrue());
        stats.put("lockedUsers", userRepository.countByAccountNonLockedFalse());
        stats.put("onLineUsers", userRepository.countByOnlineTrue());
       // stats.put("recentUsers", userRepository.countByCreatedAtAfter(LocalDateTime.now().minusDays(7)));

        return ResponseEntity.ok(stats);
    }

    @PostMapping("/tokens/revoke")
    @PreAuthorize("hasAuthority('admin:token:revoke')")
    public ResponseEntity<ApiResponse> revokeToken(@RequestBody String token) {
        if (!jwtService.isTokenValid(token)) {
            return ResponseEntity.badRequest().body(new ApiResponse(false, "Invalid token"));
        }

        Instant expiry = jwtService.extractExpiration(token).toInstant();
        blackListedTokenRepository.save(new BlackListedToken(token, expiry));

        return ResponseEntity.ok(new ApiResponse(true, "Token successfully revoked"));
    }

    //   +++++++++++++++++++++++++++++++++++++++ Self Management ++++++++++++++++++++++++++++++++++++++++++++++++++++++
    @GetMapping("/me")
    @PreAuthorize("hasAuthority('admin:self:read')")
    public ResponseEntity<UserResponseDto> getCurrentUser(@AuthenticationPrincipal UserDetails userDetails) {
        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new EntityNotFoundException("User not found"));
        return ResponseEntity.ok(UserMapper.mapToDto(user));
    }

    @PutMapping("/me")
    @PreAuthorize("hasAuthority('admin:self:update')")
    public ResponseEntity<UserResponseDto> updateSelf(
            @RequestBody Map<String, Object> updates,
            @AuthenticationPrincipal UserDetails currentUser) {

        UserResponseDto updatedUser = userService.updateSelf(updates, currentUser);
        return ResponseEntity.ok(updatedUser);
    }


    //   +++++++++++++++++++++++++++++++++++++++ Test Endpoint ++++++++++++++++++++++++++++++++++++++++++++++++++++++

    @GetMapping("/test/permissions")
    public ResponseEntity<?> testPermissions(Authentication authentication) {
        return ResponseEntity.ok(authentication.getAuthorities());
    }
}
