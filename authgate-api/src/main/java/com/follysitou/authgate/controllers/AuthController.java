package com.follysitou.authgate.controllers;

import com.follysitou.authgate.dtos.*;
import com.follysitou.authgate.models.BlackListedToken;
import com.follysitou.authgate.models.User;
import com.follysitou.authgate.repository.BlackListedTokenRepository;
import com.follysitou.authgate.service.AuthService;
import com.follysitou.authgate.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.time.Instant;

@RestController
@Slf4j
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {

    private final AuthService authService;

    private final JwtService jwtService;

    private final BlackListedTokenRepository blackListedTokenRepository;

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
    public ResponseEntity<?> logout(HttpServletRequest request) {

        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body(new ApiResponse(false, "Token manquant"));
        }

        String token = authHeader.substring(7);

        try {
            if (jwtService.isTokenValid(token) && !blackListedTokenRepository.existsById(token)) {
                Instant expiryDate = jwtService.extractExpiration(token).toInstant();
                blackListedTokenRepository.save(new BlackListedToken(token, expiryDate));
                return ResponseEntity.ok(new ApiResponse(true, "Déconnexion réussie"));
            }
        } catch (Exception e) {
            log.warn("Échec de déconnexion pour le token: {}", token, e);
        }

        return ResponseEntity.badRequest().body(new ApiResponse(false, "Token invalide ou déjà révoqué"));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponse> refreshToken(
            @CookieValue(name = "refreshToken") String oldRefreshToken,
            HttpServletResponse response) {

        // 1. Invalider l'ancien token
        String email = jwtService.extractUsername(oldRefreshToken);
        User user = (User) authService.loadUserByUsername(email);

        if (!jwtService.validateToken(oldRefreshToken, user)) {
            throw new RuntimeException("Refresh token invalide");
        }

        // 2. Blacklister l'ancien token (rotation)
        blackListedTokenRepository.save(
                new BlackListedToken(oldRefreshToken, jwtService.extractExpiration(oldRefreshToken).toInstant())
        );

        // 3. Générer nouveaux tokens
        String newAccessToken = jwtService.generateToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);

        // 4. Mettre à jour le cookie
        response.addHeader(HttpHeaders.SET_COOKIE, createRefreshTokenCookie(newRefreshToken).toString());

        // 5. Réponse (sans exposer le refresh token dans le body)
        return ResponseEntity.ok()
                .body(new AuthResponse(newAccessToken, user.getEmail()));
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

    private ResponseCookie createRefreshTokenCookie(String refreshToken) {
        return ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(true) // En production uniquement avec HTTPS
                .sameSite("Strict")
                .maxAge(Duration.ofDays(15))
                .path("/api/auth/refresh-token")
                .build();
    }
}
