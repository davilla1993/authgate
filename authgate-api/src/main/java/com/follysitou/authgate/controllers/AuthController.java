package com.follysitou.authgate.controllers;

import com.follysitou.authgate.dtos.auth.*;
import com.follysitou.authgate.models.BlackListedToken;
import com.follysitou.authgate.models.RefreshToken;
import com.follysitou.authgate.models.User;
import com.follysitou.authgate.repository.BlackListedTokenRepository;
import com.follysitou.authgate.repository.RefreshTokenRepository;
import com.follysitou.authgate.repository.UserRepository;
import com.follysitou.authgate.service.AuthService;
import com.follysitou.authgate.service.JwtService;
import com.follysitou.authgate.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@Slf4j
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {

    private final JwtService jwtService;

    private final AuthService authService;

    private final UserRepository userRepository;

    private final RefreshTokenService refreshTokenService;

    private final RefreshTokenRepository refreshTokenRepository;

    private final BlackListedTokenRepository blackListedTokenRepository;



    @Value("${app.account.lock-time-minutes}")
    private int accountLockTimeMinutes;

    @Value("${app.security.csrf.logout-enabled:false}") // Valeur par défaut: false
    private boolean csrfEnabledForLogout;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
        try {
            ApiResponse response = authService.register(registerRequest);
            if (response.isSuccess()) {
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.badRequest().body(response);
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse(false, "Erreur lors de l'inscription : " + e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            AuthResponse response = authService.login(loginRequest);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse(false, "Erreur de connexion : " + e.getMessage()));
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyCode(@Valid @RequestBody VerificationRequest verificationRequest) {
        try {
            AuthResponse response = authService.verifyCode(verificationRequest);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse(false, "Erreur de vérification : " + e.getMessage()));
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest forgotPasswordRequest) {
        try {
            ApiResponse response = authService.forgotPassword(forgotPasswordRequest);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse(false, "Erreur : " + e.getMessage()));
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest resetPasswordRequest) {
        try {
            ApiResponse response = authService.resetPassword(resetPasswordRequest);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse(false, "Erreur : " + e.getMessage()));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            HttpServletRequest request,
            HttpServletResponse response,
            @CookieValue(name = "refreshToken", required = false) String refreshToken,
            @RequestHeader(name = "X-XSRF-TOKEN", required = false) String csrfHeader,
            @CookieValue(name = "XSRF-TOKEN", required = false) String csrfCookie
    ) {
        // 1. Vérification CSRF (seulement si le endpoint est protégé)
        if (csrfEnabledForLogout && (csrfHeader == null || !csrfHeader.equals(csrfCookie))) {
            log.warn("Tentative de logout sans token CSRF valide - IP: {}", request.getRemoteAddr());
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse(false, "Token CSRF manquant ou invalide"));
        }

        // 2. Extraction du token JWT
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse(false, "Token d'authentification manquant"));
        }
        String accessToken = authHeader.substring(7);

        try {
            // 3. Révocation du access token
            if (jwtService.isTokenValid(accessToken)) {
                Instant expiry = jwtService.extractExpiration(accessToken).toInstant();
                blackListedTokenRepository.save(new BlackListedToken(accessToken, expiry));
            }

            // 4. Révocation du refresh token (si présent)
            if (refreshToken != null && jwtService.isTokenValid(refreshToken)) {
                refreshTokenService.revokeRefreshToken(refreshToken);

                // Nettoyage du cookie
                ResponseCookie cleanCookie = ResponseCookie.from("refreshToken", "")
                        .maxAge(0)
                        .path("/api/auth")
                        .build();
                response.addHeader(HttpHeaders.SET_COOKIE, cleanCookie.toString());
            }

            // 5. Journalisation
            String username = jwtService.extractUsername(accessToken);
            log.info("Logout réussi pour l'utilisateur : {}", username);

            return ResponseEntity.ok()
                    .body(new ApiResponse(true, "Déconnexion réussie"));

        } catch (Exception e) {
            log.error("Erreur lors du logout", e);
            return ResponseEntity.internalServerError()
                    .body(new ApiResponse(false, "Erreur interne lors de la déconnexion"));
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponse> refreshToken(
            @CookieValue(name = "refreshToken") String oldRefreshToken,
            HttpServletResponse response) {

        // 1. Vérifier l'ancien token
        RefreshToken oldToken = refreshTokenService.verifyRefreshToken(oldRefreshToken);
        User user = oldToken.getUser();

        // 2. Révoquer l'ancien token (rotation)
        oldToken.setRevoked(true);
        refreshTokenRepository.save(oldToken);

        // 3. Générer nouveaux tokens
        String newAccessToken = jwtService.generateToken(user);
        RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user);

        // 4. Mettre à jour le cookie
        response.addHeader(HttpHeaders.SET_COOKIE,
                createRefreshTokenCookie(newRefreshToken.getTokenHash()).toString());

        // 5. Retourner la réponse
        return ResponseEntity.ok(new AuthResponse(newAccessToken, null)); // Ne pas exposer le refresh token
    }

    @PostMapping("/lock-account")
    @PreAuthorize("hasAuthority('user_manage')")
    public ResponseEntity<?> lockUserAccount(@Valid @RequestBody LockAccountRequest request,
                                             @AuthenticationPrincipal UserDetails adminDetails) {
        try {

            // Récupérer l'email de l'admin connecté
            String adminEmail = adminDetails.getUsername();

            ApiResponse response = authService.lockUserAccount(
                    request.getEmail(),
                    request.getReason(),
                    adminEmail);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse(false, "Erreur : " + e.getMessage()));
        }
    }

    @PreAuthorize("hasAuthority('user_manage')")
    public ResponseEntity<?> unlockUserAccount(@RequestParam String email) {
        try {
            ApiResponse response = authService.unlockUserAccount(email);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse(false, "Erreur : " + e.getMessage()));
        }
    }

    @GetMapping("/locked-accounts")
    public List<User> getLockedAccounts() {
        return userRepository.findByAccountNonLockedFalse();
    }

    @PostMapping("/revoke-token")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> revokeToken(@RequestBody String token) {
        if (!jwtService.isTokenValid(token)) {
            return ResponseEntity.badRequest().body(new ApiResponse(false, "Token invalide"));
        }

        Instant expiry = jwtService.extractExpiration(token).toInstant();
        blackListedTokenRepository.save(new BlackListedToken(token, expiry));

        return ResponseEntity.ok(new ApiResponse(true, "Token révoqué avec succès"));
    }

    @GetMapping("/account-status/{email}")
    @PreAuthorize("hasAuthority('user_manage')")
    public ResponseEntity<?> getAccountStatus(@PathVariable @Email String email) {
        try {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));

            Map<String, Object> response = new HashMap<>();
            response.put("email", user.getEmail());
            response.put("isLocked", !user.isAccountNonLocked());
            response.put("status", user.isAccountNonLocked() ? "ACTIF" : "VERROUILLÉ");
            response.put("lastLoginAttempt", user.getLastLoginAttempt());
            response.put("passwordChangedAt", user.getPasswordChangedAt());

            if (!user.isAccountNonLocked()) {
                response.put("lockReason", user.getLockReason());
                response.put("lockedSince", user.getManualLockTime());
                response.put("lockedBy", user.getLockedBy());

                if (user.getLockTime() != null) { // Verrouillage automatique
                    response.put("autoUnlockTime", user.getLockTime().plusMinutes(accountLockTimeMinutes));
                }
            }

            response.put("failedAttempts", user.getFailedAttempts());
            response.put("lastUpdate", user.getUpdatedAt());

            // Calcul de l'ancienneté du mot de passe (en jours)
            if (user.getPasswordChangedAt() != null) {
                long passwordAgeDays = ChronoUnit.DAYS.between(
                        user.getPasswordChangedAt(),
                        LocalDateTime.now()
                );
                response.put("passwordAgeDays", passwordAgeDays);
            }

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse(false, "Erreur : " + e.getMessage()));
        }
    }
    private ResponseCookie createRefreshTokenCookie(String refreshToken) {
        return ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(true) // En production uniquement avec HTTPS
                .sameSite("Strict")
                .maxAge(Duration.ofDays(30))
                .path("/api/auth/refresh-token")
                .build();
    }
}
