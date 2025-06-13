package com.follysitou.authgate.scheduling;

import com.follysitou.authgate.models.User;
import com.follysitou.authgate.repository.BlackListedTokenRepository;
import com.follysitou.authgate.repository.UserRepository;
import com.follysitou.authgate.service.EmailService;
import com.follysitou.authgate.service.RefreshTokenService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.*;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class SystemScheduler {

    private final EmailService emailService;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final BlackListedTokenRepository blackListedTokenRepository;

   /* @Scheduled(cron = "0 0 * * * *") // Toutes les heures
    @Transactional
    public void cleanExpiredBlacklistedTokens() {

        blackListedTokenRepository.deleteByExpiryDateBefore(Instant.now());
    }*/

    /*@Scheduled(cron = "0 0 9 * * ?") // Tous les jours à 9h
    public void checkPasswordExpiration() {
        LocalDateTime expirationThreshold = LocalDateTime.now().minusDays(90);
        List<User> users = userRepository.findByPasswordChangedAtBefore(expirationThreshold);
        users.forEach(user -> emailService.sendPasswordExpirationWarning(
                user.getEmail(),
                "Votre mot de passe va expirer bientôt",
                "Votre mot de passe n'a pas été changé depuis plus de 90 jours."
        ));
    }

    @Scheduled(cron = "0 0 3 * * ?") // Tous les jours à 3h du matin
    @Transactional
    public void removeUnverifiedAccounts() {
        Instant threshold = LocalDateTime.now().minusDays(30)
                .atZone(ZoneId.systemDefault()).toInstant();
        List<User> oldUnverified = userRepository.findAll().stream()
                .filter(u -> !u.isEnabled() && u.getCreatedAt().isBefore(threshold))
                .collect(Collectors.toList());
        userRepository.deleteAll(oldUnverified);
    }

    @Scheduled(cron = "0 0 3 * * ?") // Tous les jours à 3h
    public void cleanExpiredRefreshTokens() {
        refreshTokenService.cleanExpiredTokens();
    }

    @Scheduled(fixedRate = 300000) // Toutes les 5 minutes
    @Transactional
    public void markInactiveUsersOffline() {
        Instant threshold = Instant.now().minus(Duration.ofMinutes(10));
        userRepository.markUsersOfflineBefore(threshold);
        log.info("Users inactive since {} marked as offline", threshold);
    }*/
}

