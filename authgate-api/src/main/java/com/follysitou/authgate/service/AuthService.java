package com.follysitou.authgate.service;

import com.follysitou.authgate.dtos.*;
import com.follysitou.authgate.models.BlackListedToken;
import com.follysitou.authgate.models.Permission;
import com.follysitou.authgate.models.Role;
import com.follysitou.authgate.models.User;
import com.follysitou.authgate.repository.BlackListedTokenRepository;
import com.follysitou.authgate.repository.PermissionRepository;
import com.follysitou.authgate.repository.RoleRepository;
import com.follysitou.authgate.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Random;
import java.util.UUID;

@Service
public class AuthService implements UserDetailsService {

    private final JwtService jwtService;
    private final EmailService emailService;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final PermissionRepository permissionRepository;
    private final BlackListedTokenRepository blackListedTokenRepository;

    @Value("${app.verification.code-expiration}")
    private long codeExpirationTime;

    public AuthService(RoleRepository roleRepository, UserRepository userRepository, PasswordEncoder passwordEncoder,
                       JwtService jwtService, EmailService emailService, @Lazy AuthenticationManager authenticationManager,
                       PermissionRepository permissionRepository, BlackListedTokenRepository blackListedTokenRepository) {

        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.emailService = emailService;
        this.authenticationManager = authenticationManager;
        this.permissionRepository = permissionRepository;
        this.blackListedTokenRepository = blackListedTokenRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Utilisateur non trouvé : " + email));
    }

    public ApiResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            return new ApiResponse(false, "Email déjà utilisé !");
        }

        User user = new User(
                request.getFirstName(),
                request.getLastName(),
                request.getEmail(),
                passwordEncoder.encode(request.getPassword())
        );

        // Générer le code de vérification
        String verificationCode = generateVerificationCode();
        user.setVerificationCode(verificationCode);
        user.setVerificationCodeExpiry(LocalDateTime.now().plusSeconds(codeExpirationTime / 1000));

        // Créer et attribuer le rôle de base
        createAndAssignBasicRole(user);
        userRepository.save(user);

        // Envoyer le code de vérification par email
        emailService.sendVerificationCode(user.getEmail(),
                                          verificationCode,
                                        "Vérification de votre email",
                "Pour finaliser votre inscription, voici votre code de vérification : ");

        return new ApiResponse(true, "Un code de vérification a été envoyé à votre adresse email");
    }

    public AuthResponse login(LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );

            User user = (User) authentication.getPrincipal();

            // Générer et envoyer le code de vérification
            String verificationCode = generateVerificationCode();
            user.setVerificationCode(verificationCode);
            user.setVerificationCodeExpiry(LocalDateTime.now().plusSeconds(codeExpirationTime / 1000));
            userRepository.save(user);

            emailService.sendVerificationCode(user.getEmail(), verificationCode,
                                                "Vérifier votre connexion",
                            "Voici votre code pour vous connecter : ");

            return new AuthResponse("Un code de vérification a été envoyé à votre email", true);

        } catch (Exception e) {
            throw new RuntimeException("Email ou mot de passe incorrect");
        }
    }

    public AuthResponse verifyCode(VerificationRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));

        if (user.getVerificationCode() == null ||
                !user.getVerificationCode().equals(request.getCode()) ||
                user.getVerificationCodeExpiry().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Code de vérification invalide ou expiré");
        }

        // Nettoyer le code de vérification
        user.setVerificationCode(null);
        user.setVerificationCodeExpiry(null);
        userRepository.save(user);

        if (!user.isEnabled()) {
            user.setEnabled(true);
        }
        userRepository.save(user);

        // Générer le token JWT
        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        return new AuthResponse(accessToken, refreshToken);
    }

    public ApiResponse forgotPassword(ForgotPasswordRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé avec cet email"));

        String resetToken = UUID.randomUUID().toString();
        user.setResetPasswordToken(resetToken);
        user.setResetPasswordTokenExpiry(LocalDateTime.now().plusHours(1));
        userRepository.save(user);

        emailService.sendPasswordResetToken(user.getEmail(), resetToken);

        return new ApiResponse(true, "Instructions de réinitialisation envoyées par email");
    }

    public ApiResponse resetPassword(ResetPasswordRequest request) {
        User user = userRepository.findByResetPasswordToken(request.getToken())
                .orElseThrow(() -> new RuntimeException("Token de réinitialisation invalide"));

        if (user.getResetPasswordTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Token de réinitialisation expiré");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setResetPasswordToken(null);
        user.setResetPasswordTokenExpiry(null);
        userRepository.save(user);

        return new ApiResponse(true, "Mot de passe réinitialisé avec succès");
    }

    public AuthResponse refreshToken(String oldRefreshToken) {
        // 1. Valider l'ancien token
        String email = jwtService.extractUsername(oldRefreshToken);
        User user = (User) loadUserByUsername(email);

        if (!jwtService.validateToken(oldRefreshToken, user)) {
            throw new RuntimeException("Refresh token invalide");
        }

        // 2. Blacklister l'ancien token
        blackListedTokenRepository.save(new BlackListedToken(oldRefreshToken, Instant.now()));

        // 3. Générer nouveaux tokens
        String newAccessToken = jwtService.generateToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);

        return new AuthResponse(newAccessToken, newRefreshToken);
    }

    private void createAndAssignBasicRole(User user) {
        // Vérifier si la permission de base existe déjà
        Permission basicPermission = permissionRepository.findByName("basic_access")
                .orElseGet(() -> {
                    Permission newPermission = new Permission();
                    newPermission.setName("basic_access");
                    newPermission.setDescription("Accès basique à l'application");
                    return permissionRepository.save(newPermission);
                });

        // Vérifier si le rôle de base existe déjà
        Role basicRole = roleRepository.findByName("ROLE_USER")
                .orElseGet(() -> {
                    Role newRole = new Role();
                    newRole.setName("ROLE_USER");
                    newRole.setDescription("Rôle utilisateur de base");
                    newRole.getPermissions().add(basicPermission);
                    return roleRepository.save(newRole);
                });

        user.getRoles().add(basicRole);
    }

    private String generateVerificationCode() {
        Random random = new Random();
        int code = 100000 + random.nextInt(900000);
        return String.valueOf(code);
    }
}

