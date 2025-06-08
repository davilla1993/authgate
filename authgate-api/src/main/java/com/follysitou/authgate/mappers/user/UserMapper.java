package com.follysitou.authgate.mappers.user;

import com.follysitou.authgate.dtos.user.AccountStatusResponseDto;
import com.follysitou.authgate.dtos.user.UserResponseDto;
import com.follysitou.authgate.models.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;

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
        dto.setOnline(user.isOnline());

        // Gestion de la photo
        if (user.getPhotoUrl() != null) {
            dto.setPhotoUrl(basePhotoUrl + "/api/users/" + user.getId() + "/photo");
            dto.setHasPhoto(true);
            dto.setPhotoLastUpdated(user.getUpdatedAt());
        } else {
            dto.setHasPhoto(false);
            dto.setPhotoUrl(null);
        }

        return dto;
    }


    public static AccountStatusResponseDto mapToStatusDto(User user) {

        AccountStatusResponseDto dto = AccountStatusResponseDto.builder()
                .email(user.getEmail())
                .isLocked(!user.isAccountNonLocked())
                .status(user.isAccountNonLocked() ? "ACTIF" : "VERROUILLÉ")
                .lastActivity(LocalDateTime.from(user.getLastActivity()))
                .passwordChangedAt(user.getPasswordChangedAt())
                .failedAttempts(user.getFailedAttempts())
                .lastUpdate(LocalDateTime.from(user.getUpdatedAt()))
                .build();

        if (!user.isAccountNonLocked()) {
            dto.setLockReason(user.getLockReason());
            dto.setLockedSince(user.getManualLockTime());
            dto.setLockedBy(user.getLockedBy());
        }

        if (user.getPasswordChangedAt() != null) {
            dto.setPasswordAgeDays(ChronoUnit.DAYS.between(
                    user.getPasswordChangedAt(),
                    LocalDateTime.now()));
        }

        return dto;
    }

}