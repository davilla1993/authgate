package com.follysitou.authgate.dtos.user;

import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccountStatusResponseDto {

    private String email;
    private boolean isLocked;
    private String status;
    private LocalDateTime lastActivity;
    private LocalDateTime passwordChangedAt;
    private String lockReason;
    private LocalDateTime lockedSince;
    private String lockedBy;
    private int failedAttempts;
    private LocalDateTime lastUpdate;
    private Long passwordAgeDays;
}
