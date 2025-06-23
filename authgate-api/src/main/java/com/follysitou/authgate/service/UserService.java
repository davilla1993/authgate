package com.follysitou.authgate.service;

import com.follysitou.authgate.dtos.auth.ApiResponse;
import com.follysitou.authgate.dtos.auth.RegisterRequest;
import com.follysitou.authgate.dtos.user.AccountStatusResponseDto;
import com.follysitou.authgate.dtos.user.UserResponseDto;
import com.follysitou.authgate.dtos.user.UserUpdateRequest;
import com.follysitou.authgate.exceptions.*;
import com.follysitou.authgate.handlers.ErrorCodes;
import com.follysitou.authgate.mappers.user.UserMapper;
import com.follysitou.authgate.models.User;
import com.follysitou.authgate.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final RoleService roleService;
    private final EmailService emailService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleHierarchyService roleHierarchyService;
    private final PasswordValidatorService passwordValidator;

    public ApiResponse createUserByAdmin(RegisterRequest request) {

        passwordValidator.validatePassword(request.getPassword());

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new ResourceAlreadyExistsException("Email already in use");
        }

        User user = new User(
                request.getFirstName(),
                request.getLastName(),
                request.getEmail(),
                passwordEncoder.encode(request.getPassword())
        );

        // Activer directement le compte
        user.setEnabled(true);
        roleService.createAndAssignBasicRole(user);
        userRepository.save(user);
        // Notifier l’utilisateur par email
        emailService.sendAccountCreatedByAdmin(user.getEmail(), user.getFirstName());

        return new ApiResponse(true, "User account successfully created and notification email sent");
    }

    public Page<UserResponseDto> getAllUsers(Boolean active, String search, Pageable pageable) {
        Page<User> users;

        if (search != null && !search.isEmpty()) {
            users = userRepository.searchByKeyword(search, pageable);
        } else if (active == null) {
            users = userRepository.findAll(pageable);
        } else {
            users = active
                    ? userRepository.findByEnabledTrue(pageable)
                    : userRepository.findByEnabledFalse(pageable);
        }
        return users.map(UserMapper::mapToDto);
    }

    public UserResponseDto getUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        return UserMapper.mapToDto(user);
    }

    public Page<UserResponseDto> getOnlineUsers(Pageable pageable) {
        return userRepository.findByOnlineTrue(pageable)
                .map(UserMapper::mapToDto);
    }

    public AccountStatusResponseDto getUserAccountStatus(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        return UserMapper.mapToStatusDto(user);
    }

     // ✅ Réservé aux ADMINS : L'admin peut modifier les informations d'un utilisateur
    public UserResponseDto updateUser(String targetEmail, UserUpdateRequest request) {
        User targetUser = userRepository.findByEmail(targetEmail)
                .orElseThrow(() -> new EntityNotFoundException("User not found: "
                                                    + targetEmail, ErrorCodes.USER_NOT_FOUND));

        boolean isTargetAdmin = targetUser.getRoles().stream()
                .anyMatch(role -> role.getName().equals("ROLE_ADMIN"));

        roleHierarchyService.checkAccountManagerAdminRestriction(isTargetAdmin,
                "Account Managers cannot modify Administrator accounts.");

        // Validation métier
        if (request.getEmail() != null && !request.getEmail().isEmpty() && !request.getEmail().equals(targetUser.getEmail())) {
            throw new InvalidOperationException("Email modification is not allowed for user updates.", ErrorCodes.INVALID_OPERATION);
        }

        if (request.getFirstName() != null) {
            targetUser.setFirstName(request.getFirstName());
        }
        if (request.getLastName() != null) {
            targetUser.setLastName(request.getLastName());
        }

        userRepository.save(targetUser);
        log.info("Admin modified user with email: {}", targetEmail);

        return UserMapper.mapToDto(targetUser);
    }

    //  ✅ Réservé aux USER : Un utilisateur peut modifier ses propres informations
    public UserResponseDto updateSelf(Map<String, Object> updates, UserDetails currentUser) {
        User currentUserEntity = userRepository.findByEmail(currentUser.getUsername())
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        // Bloque la modification de l'email
        if (updates.containsKey("email")) {
            throw new InvalidOperationException("Email modification is not allowed");
        }

        // Applique les modifications
        if (updates.containsKey("firstName")) currentUserEntity.setFirstName((String) updates.get("firstName"));
        if (updates.containsKey("lastName")) currentUserEntity.setLastName((String) updates.get("lastName"));

        userRepository.save(currentUserEntity);
        log.info("User modified their own profile");

        return UserMapper.mapToDto(currentUserEntity);
    }

    public void deleteUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        user.setDeleted(true);
        user.setDeletedBy(getCurrentAuditor());
        user.setDeletedAt(Instant.now());
        userRepository.save(user);

        log.info("ADMIN {} deleted user {}", getCurrentAuditor(), user.getEmail());
    }

    public void disableUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));
        user.setEnabled(false);
        userRepository.save(user);

        log.info("ADMIN has deactivated user {}", user.getEmail());
    }

    public void enableUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));
        user.setEnabled(true);
        userRepository.save(user);
        log.info("ADMIN has actived user {}", user.getEmail());
    }

    // Méthode utilitaire pour récupérer l'utilisateur courant
    private String getCurrentAuditor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return "system";
        }
        if (authentication.getPrincipal() instanceof UserDetails) {
            return ((UserDetails) authentication.getPrincipal()).getUsername();
        }
        return authentication.getName();
    }
}
