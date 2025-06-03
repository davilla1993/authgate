package com.follysitou.authgate.service;

import com.follysitou.authgate.dtos.user.UserResponseDto;
import com.follysitou.authgate.mappers.user.UserMapper;
import com.follysitou.authgate.models.User;
import com.follysitou.authgate.repository.UserRepository;
import io.swagger.v3.oas.models.info.Contact;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

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
                .orElseThrow(() -> new RuntimeException("User not found"));

        return UserMapper.mapToDto(user);
    }


    public List<UserResponseDto> getOnlineUsers() {
        LocalDateTime threshold = LocalDateTime.now().minusMinutes(10);
        return userRepository.findByLastLoginAttemptAfter(threshold)
                .stream()
                .map(UserMapper::mapToDto)
                .collect(Collectors.toList());
    }

    public UserResponseDto updateUser(Long id, Map<String, Object> updates, String adminEmail) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));

        if (updates.containsKey("firstName")) user.setFirstName((String) updates.get("firstName"));
        if (updates.containsKey("lastName")) user.setLastName((String) updates.get("lastName"));

        if (updates.containsKey("email")) {
            throw new RuntimeException("La modification de l'adresse email n'est pas autorisée");
        }

        userRepository.save(user);
        log.info("ADMIN {} a modifié l'utilisateur {}", adminEmail, user.getEmail());

        return UserMapper.mapToDto(user);
    }

    public void deleteUser(Long id, String adminEmail) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));
        userRepository.delete(user);
        log.info("ADMIN {} a supprimé l'utilisateur {}", adminEmail, user.getEmail());
    }

    public void disableUser(Long id, String adminEmail) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));
        user.setEnabled(false);
        userRepository.save(user);
        log.info("ADMIN {} a désactivé l'utilisateur {}", adminEmail, user.getEmail());
    }

    public void enableUser(Long id, String adminEmail) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));
        user.setEnabled(true);
        userRepository.save(user);
        log.info("ADMIN {} a activé l'utilisateur {}", adminEmail, user.getEmail());
    }

    public void resetPassword(Long id, String newPassword, String adminEmail) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));

        user.setPassword(passwordEncoder.encode(newPassword));
        user.recordPasswordChange();
        userRepository.save(user);

        log.info("ADMIN {} a réinitialisé le mot de passe de {}", adminEmail, user.getEmail());
    }

}
