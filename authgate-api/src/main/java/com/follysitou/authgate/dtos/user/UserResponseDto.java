package com.follysitou.authgate.dtos.user;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserResponseDto {

    private Long id;
    private String firstName;
    private String lastName;
    private String email;
    private boolean enabled;
    private boolean accountNonLocked;
    private LocalDateTime lastLoginAttempt;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
