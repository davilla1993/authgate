package com.follysitou.authgate.controllers;

import com.follysitou.authgate.dtos.user.UserResponseDto;
import com.follysitou.authgate.exceptions.EntityNotFoundException;
import com.follysitou.authgate.mappers.user.UserMapper;
import com.follysitou.authgate.models.User;
import com.follysitou.authgate.repository.UserRepository;
import com.follysitou.authgate.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@PreAuthorize("hasRole('USER')")
public class UserController {

    private final UserService userService;
    private final UserRepository userRepository;

    @GetMapping("/me")
    @PreAuthorize("hasAuthority('user:self:read')")
    public ResponseEntity<UserResponseDto> getCurrentUser(@AuthenticationPrincipal UserDetails userDetails) {
        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new EntityNotFoundException("User not found"));
        return ResponseEntity.ok(UserMapper.mapToDto(user));
    }

    @PutMapping("/me")
    @PreAuthorize("hasAnyAuthority('user:self:update')")
    public ResponseEntity<UserResponseDto> updateSelf(
            @RequestBody Map<String, Object> updates,
            @AuthenticationPrincipal UserDetails currentUser) {

        UserResponseDto updatedUser = userService.updateSelf(updates, currentUser);
        return ResponseEntity.ok(updatedUser);
    }

}

