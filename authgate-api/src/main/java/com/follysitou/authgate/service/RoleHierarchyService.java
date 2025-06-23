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

    /**
     * Vérifie si l'utilisateur courant (l'acteur) est un ROLE_ACCOUNT_MANAGER
     * et si la cible de l'opération est un ROLE_ADMIN ou une entité liée à ROLE_ADMIN.
     * Si c'est le cas, une exception InvalidOperationException est levée.
     *
     * @param isTargetAdmin True si la cible de l'opération est un ADMIN ou le rôle ADMIN.
     * @param errorMessage Le message d'erreur spécifique à afficher si l'opération est interdite.
     */
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
