package com.follysitou.authgate.controllers;

import com.follysitou.authgate.dtos.auth.ApiResponse;
import com.follysitou.authgate.dtos.user.UserResponseDto;
import com.follysitou.authgate.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping
    public ResponseEntity<Page<UserResponseDto>> getAllUsers(
            @RequestParam(required = false) Boolean active,
            @RequestParam(required = false) String search,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size
    ) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        return ResponseEntity.ok(userService.getAllUsers(active, search, pageable));
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserResponseDto> getUserById(@PathVariable Long id) {
        UserResponseDto userDto = userService.getUserById(id);
        return ResponseEntity.ok(userDto);
    }

    @GetMapping("/online")
    public ResponseEntity<List<UserResponseDto>> getOnlineUsers() {
        return ResponseEntity.ok(userService.getOnlineUsers());
    }

    @PutMapping("/{id}")
    public ResponseEntity<UserResponseDto> updateUser(
            @PathVariable Long id,
            @RequestBody Map<String, Object> updates,
            @AuthenticationPrincipal UserDetails admin
    ) {
        UserResponseDto updated = userService.updateUser(id, updates, admin.getUsername());
        return ResponseEntity.ok(updated);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteUser(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails admin
    ) {
        userService.deleteUser(id, admin.getUsername());
        return ResponseEntity.ok(new ApiResponse(true, "Utilisateur supprimé"));
    }

    @PutMapping("/{id}/disable")
    public ResponseEntity<?> disableUser(@PathVariable Long id, @AuthenticationPrincipal UserDetails admin) {
        userService.disableUser(id, admin.getUsername());
        return ResponseEntity.ok(new ApiResponse(true, "Utilisateur désactivé"));
    }

    @PutMapping("/{id}/enable")
    public ResponseEntity<?> enableUser(@PathVariable Long id, @AuthenticationPrincipal UserDetails admin) {
        userService.enableUser(id, admin.getUsername());
        return ResponseEntity.ok(new ApiResponse(true, "Utilisateur activé"));
    }

    @PutMapping("/{id}/reset-password")
    public ResponseEntity<?> resetPasswordByAdmin(
            @PathVariable Long id,
            @RequestParam String newPassword,
            @AuthenticationPrincipal UserDetails admin
    ) {
        userService.resetPassword(id, newPassword, admin.getUsername());
        return ResponseEntity.ok(new ApiResponse(true, "Mot de passe réinitialisé"));
    }
}

