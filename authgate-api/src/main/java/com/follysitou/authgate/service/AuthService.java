package com.follysitou.authgate.service;

import com.follysitou.authgate.dtos.auth.*;
import com.follysitou.authgate.exceptions.*;
import com.follysitou.authgate.models.BlackListedToken;
import com.follysitou.authgate.models.RefreshToken;
import com.follysitou.authgate.models.User;
import com.follysitou.authgate.repository.BlackListedTokenRepository;
import com.follysitou.authgate.repository.RefreshTokenRepository;
import com.follysitou.authgate.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.BadRequestException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;


@Service
@Slf4j
public class AuthService implements UserDetailsService {

    private final JwtService jwtService;
    private final EmailService emailService;
    private final RoleService roleService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserSessionService userSessionService;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordValidatorService passwordValidator;
    private final AuthenticationManager authenticationManager;
    private final BlackListedTokenRepository blackListedTokenRepository;


    @Value("${app.security.csrf.logout-enabled}")
    private boolean csrfEnabledForLogout;

    @Value("${app.verification.code-expiration}")
    private long codeExpirationTime;

    @Value("${app.account.lock-time-minutes}")
    private int accountLockTimeMinutes;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService,
                       EmailService emailService,
                       RoleService roleService,
                       UserSessionService userSessionService,
                       RefreshTokenService refreshTokenService,
                       RefreshTokenRepository refreshTokenRepository,
                       PasswordValidatorService passwordValidator,
                       @Lazy AuthenticationManager authenticationManager,
                       BlackListedTokenRepository blackListedTokenRepository) {

        this.roleService = roleService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.emailService = emailService;
        this.userSessionService = userSessionService;
        this.refreshTokenService = refreshTokenService;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordValidator = passwordValidator;
        this.authenticationManager = authenticationManager;
        this.blackListedTokenRepository = blackListedTokenRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user =  userRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + email));

        if (!user.isEnabled()) {
            throw new AccountDisableException("The user account is disabled.");
        }

        return user;
    }

    public ApiResponse register(RegisterRequest request) {

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new ResourceAlreadyExistsException("Email already in use");
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
        roleService.createAndAssignBasicRole(user);
        userRepository.save(user);

        // Envoyer le code de vérification par email
        emailService.sendVerificationCode(user.getEmail(), verificationCode, user.getFirstName());

        return new ApiResponse(true, "A verification code has been sent to your email address");
    }

    public AuthResponse login(LoginRequest request) {
        try {
            Optional<User> userOptional = userRepository.findByEmail(request.getEmail());
            if (userOptional.isPresent()) {
                User user = userOptional.get();

                // Vérifier si le compte est activé
                if (!user.isEnabled()) {
                    throw new AccountDisableException("The user account is disabled.");
                }

                // Vérifier si le compte est verrouillé
                if (user.isAccountLocked()) {
                    if (user.getLockTime().plusMinutes(accountLockTimeMinutes).isAfter(LocalDateTime.now())) {
                        throw new BusinessException("Your account is locked. Please try again later.");
                    } else {
                        user.unlockAccount();
                        userRepository.save(user);
                    }
                }

                // Authentification
                Authentication authentication = authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
                );

                // Réinitialiser les tentatives échouées après succès
                user.setFailedAttempts(0);
                user.setLastActivity(Instant.now());
                userRepository.save(user);

                User authenticatedUser = (User) authentication.getPrincipal();

                // Ne générer un nouveau code QUE si l'ancien est expiré ou inexistant
                if (authenticatedUser.getVerificationCode() == null ||
                        authenticatedUser.getVerificationCodeExpiry().isBefore(LocalDateTime.now())) {

                    String verificationCode = generateVerificationCode();
                    authenticatedUser.setVerificationCode(verificationCode);
                    authenticatedUser.setVerificationCodeExpiry(LocalDateTime.now().plusSeconds(codeExpirationTime / 1000));
                    userRepository.save(authenticatedUser);

                    emailService.sendVerificationCode(
                            authenticatedUser.getEmail(),
                            verificationCode, authenticatedUser.getFirstName());

                    return new AuthResponse("A verification code has been sent to your email address", true);
                } else {
                    return new AuthResponse("A verification code has already been sent", true);
                }
            }

            throw new EntityNotFoundException("User not found");

        } catch (BadCredentialsException e) {
            userRepository.findByEmail(request.getEmail()).ifPresent(user -> {
                boolean justLocked = user.incrementFailedAttempts(); // logique métier
                userRepository.save(user);

                if (justLocked) {
                    log.info(">>> ENVOI DE MAIL DE VERROUILLAGE À {}", user.getEmail());

                    emailService.sendAccountLockedEmail(
                            user.getEmail(),
                            "Votre compte a été verrouillé après plusieurs tentatives de connexion infructueuses",
                            user.getLockTime(),
                            user.getLockTime().plusMinutes(accountLockTimeMinutes),
                            user.getFirstName()
                    );

                    throw new BusinessException("Account locked for multiple unsuccessful login attempts");
                }
            });

            throw new InvalidParameterException("Invalid email or password");

        } catch (Exception e) {
            throw new BusinessException("Login error: " + e.getMessage());
        }
    }



    @Transactional
    public AuthResponse verifyCode(VerificationRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        if (user.getVerificationCode() == null ||
                !user.getVerificationCode().equals(request.getCode()) ||
                user.getVerificationCodeExpiry().isBefore(LocalDateTime.now())) {
            throw new InvalidOperationException("Invalid or expired verification code");
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

        return new AuthResponse(accessToken, refreshToken, "Succès");
    }

    public ApiResponse forgotPassword(ForgotPasswordRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new EntityNotFoundException("User not found with this email"));

        String resetToken = UUID.randomUUID().toString();
        user.setResetPasswordToken(resetToken);
        user.setResetPasswordTokenExpiry(LocalDateTime.now().plusHours(1));
        userRepository.save(user);

        emailService.sendPasswordResetToken(user.getEmail(), resetToken);

        return new ApiResponse(true, "Reset instructions sent by email");
    }

    @Transactional
    public ApiResponse resetPassword(ResetPasswordRequest request) throws BadRequestException {
        User user = userRepository.findByResetPasswordToken(request.getToken())
                .orElseThrow(() -> new InvalidOperationException("Invalid reset token"));

        if (user.getResetPasswordTokenExpiry().isBefore(LocalDateTime.now())) {
            user.setResetPasswordToken(null);
            user.setResetPasswordTokenExpiry(null);
            userRepository.save(user);

            throw new InvalidOperationException("Reset token has expired");
        }

        try {

            passwordValidator.validatePassword(request.getNewPassword());

            user.setPassword(passwordEncoder.encode(request.getNewPassword()));
            user.setResetPasswordToken(null);
            user.setResetPasswordTokenExpiry(null);
            user.recordPasswordChange();
            userRepository.save(user);

            // Invalidation des sessions existantes
            userSessionService.invalidateAllSessions(user.getId());

            emailService.sendPasswordChangeNotification(user.getEmail(), user.getFirstName());

            return new ApiResponse(true, "Password reset successfully");

        } catch (IllegalArgumentException e) {
            throw new BadRequestException(e.getMessage());
        }

    }

    @Transactional
    public AuthResponse refreshToken(String oldRefreshToken, HttpServletResponse response) {
        // 1. Validate the old refresh token (from persistent storage)
        RefreshToken storedOldToken = refreshTokenService.verifyRefreshToken(oldRefreshToken);
        User user = storedOldToken.getUser();

        // 2. Revoke the old refresh token in the database
        storedOldToken.setRevoked(true);
        storedOldToken.setRevoked(true); // Set revocation timestamp
        refreshTokenRepository.save(storedOldToken);

        // 3. (Optional but recommended for an extra layer of security) Blacklist the raw old refresh token string
        // This prevents the raw string from being reused even if the DB record is somehow missed
        blackListedTokenRepository.save(new BlackListedToken(oldRefreshToken, Instant.now()));

        // 4. Generate new Access Token
        String newAccessToken = jwtService.generateToken(user);

        // 5. Generate a new Refresh Token and save it
        RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user);

        // 6. Add the new refresh token to a HttpOnly cookie
        response.addHeader(HttpHeaders.SET_COOKIE,
                createRefreshTokenCookie(newRefreshToken.getTokenHash()).toString());

        return new AuthResponse(newAccessToken, null);
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

    public ApiResponse lockUserAccount(String email, String reason, String adminEmail) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        if (user.isAccountLocked()) {
            throw new BusinessException("Account is already locked");
        }

        user.manualLock(reason, adminEmail);
        userRepository.save(user);

        // Log l'action
        log.info("Compte {} verrouillé par {} pour raison : {}", email, adminEmail, reason);

        emailService.sendAccountManuallyLockedEmail(
                user.getEmail(),
                "Votre compte a été verrouillé",
                reason
        );

        return new ApiResponse(true, "Account successfully locked");
    }

    public ApiResponse unlockUserAccount(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        if (!user.isAccountLocked()) {
            throw new BusinessException("Account is not locked");
        }

        user.unlockAccount();
        userRepository.save(user);

        emailService.sendAccountUnlockedEmail(user.getEmail(),
                "Votre compte a été déverrouillé par un administrateur. " +
                        "Vous pouvez maintenant vous connecter normalement.");

        return new ApiResponse(true, "Account successfully unlocked");
    }

    public ApiResponse logout(HttpServletRequest request,
                              HttpServletResponse response,
                              String refreshToken,
                              String csrfHeader,
                              String csrfCookie) {

        // Vérification CSRF
        if (csrfEnabledForLogout && (csrfHeader == null || !csrfHeader.equals(csrfCookie))) {
            log.warn("Logout attempt without valid CSRF token - IP: {}", request.getRemoteAddr());
            return new ApiResponse(false, "Missing or invalid CSRF token");
        }

        // Extraction du token
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return new ApiResponse(false, "Missing authentication token");
        }
        String accessToken = authHeader.substring(7);

        try {
            // Invalidation access token
            if (jwtService.isTokenValid(accessToken)) {
                Instant expiry = jwtService.extractExpiration(accessToken).toInstant();
                blackListedTokenRepository.save(new BlackListedToken(accessToken, expiry));
            }

            // Invalidation refresh token
            if (refreshToken != null && jwtService.isTokenValid(refreshToken)) {
                refreshTokenService.revokeRefreshToken(refreshToken);
                clearRefreshTokenCookie(response);
            }

            String username = jwtService.extractUsername(accessToken);
            log.info("User successfully logged out : {}", username);

            return new ApiResponse(true, "Logout successful");

        } catch (Exception e) {
            log.error("Erreur lors du logout", e);
            return new ApiResponse(false, "Internal error while logging out");
        }
    }

    private void clearRefreshTokenCookie(HttpServletResponse response) {
        ResponseCookie cleanCookie = ResponseCookie.from("refreshToken", "")
                .maxAge(0)
                .path("/api/auth")
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cleanCookie.toString());
    }

    private String generateVerificationCode() {
        Random random = new Random();
        int code = 100000 + random.nextInt(900000);
        return String.valueOf(code);
    }
}

