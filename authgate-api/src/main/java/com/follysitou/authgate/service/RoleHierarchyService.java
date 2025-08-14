package com.follysitou.authgate.service;

import com.follysitou.authgate.exceptions.InvalidOperationException;
import com.follysitou.authgate.exceptions.UnauthorizedException;
import com.follysitou.authgate.handlers.ErrorCodes;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class RoleHierarchyService {

    public void checkAccountManagerAdminRestriction(boolean isTargetAdmin, String errorMessage) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new UnauthorizedException("User not authenticated.", ErrorCodes.UNAUTHORIZED_ACCESS);
        }

        boolean isAccountManager = authentication.getAuthorities().stream()
                .anyMatch(grantedAuthority ->
                        grantedAuthority.getAuthority().equals("ROLE_ACCOUNT_MANAGER"));

        if (isAccountManager && isTargetAdmin) {
            log.warn("Account Manager '{}' attempted an operation restricted on ADMIN target: {}",
                    authentication.getName(), errorMessage);
            throw new InvalidOperationException(errorMessage, ErrorCodes.FORBIDDEN_ACCESS);
        }
    }
}
