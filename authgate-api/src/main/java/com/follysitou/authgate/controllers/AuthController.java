package com.follysitou.authgate.controllers;

import com.follysitou.authgate.dtos.*;
import com.follysitou.authgate.models.BlackListedToken;
import com.follysitou.authgate.repository.BlackListedTokenRepository;
import com.follysitou.authgate.service.AuthService;
import com.follysitou.authgate.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

@RestController
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

        if (jwtService.isTokenValid(token)) {
            Instant expiryDate = jwtService.extractExpiration(token).toInstant();
            blackListedTokenRepository.save(new BlackListedToken(token, expiryDate));
            return ResponseEntity.ok(new ApiResponse(true, "Déconnexion réussie"));
        }

        return ResponseEntity.badRequest().body(new ApiResponse(false, "Token invalide"));
    }

}
