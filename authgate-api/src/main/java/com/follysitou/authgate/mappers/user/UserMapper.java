package com.follysitou.authgate.mappers.user;

import com.follysitou.authgate.dtos.user.UserResponseDto;
import com.follysitou.authgate.models.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.ZoneOffset;

@Service
public class UserMapper {

    @Value("${app.base-url}")
    private static String basePhotoUrl;


    public static UserResponseDto mapToDto(User user) {
        UserResponseDto dto = new UserResponseDto();
        dto.setId(user.getId());
        dto.setFirstName(user.getFirstName());
        dto.setLastName(user.getLastName());
        dto.setEmail(user.getEmail());
        dto.setEnabled(user.isEnabled());
        dto.setAccountNonLocked(user.isAccountNonLocked());
        dto.setLastLoginAttempt(user.getLastLoginAttempt());
        dto.setCreatedAt(user.getCreatedAt());
        dto.setUpdatedAt(user.getUpdatedAt());

        // Gestion de la photo
        if (user.getPhotoUrl() != null) {
            dto.setPhotoUrl(basePhotoUrl + "/api/users/" + user.getId() + "/photo");
            dto.setHasPhoto(true);
            dto.setPhotoLastUpdated(user.getUpdatedAt().toInstant(ZoneOffset.UTC));
        } else {
            dto.setHasPhoto(false);
            dto.setPhotoUrl(null);
        }

        return dto;
    }
}