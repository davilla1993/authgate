package com.follysitou.authgate.mappers.user;

import com.follysitou.authgate.dtos.user.UserResponseDto;
import com.follysitou.authgate.models.User;
import org.springframework.stereotype.Service;

@Service
public class UserMapper {

    public static UserResponseDto mapToDto(User user) {
        return new UserResponseDto(
                user.getId(),
                user.getFirstName(),
                user.getLastName(),
                user.getEmail(),
                user.isEnabled(),
                user.isAccountNonLocked(),
                user.getLastLoginAttempt(),
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }

}
