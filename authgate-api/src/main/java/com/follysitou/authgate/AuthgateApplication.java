package com.follysitou.authgate;

import com.follysitou.authgate.models.User;
import com.follysitou.authgate.repository.BlackListedTokenRepository;
import com.follysitou.authgate.repository.UserRepository;
import com.follysitou.authgate.service.EmailService;
import com.follysitou.authgate.service.RefreshTokenService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@SpringBootApplication
@RequiredArgsConstructor
public class AuthgateApplication {

	private final EmailService emailService;
	private final UserRepository userRepository;
	private final RefreshTokenService refreshTokenService;
	private final BlackListedTokenRepository blackListedTokenRepository;


	public static void main(String[] args) {
		SpringApplication.run(AuthgateApplication.class, args);
	}

	@Scheduled(cron = "0 0 * * * *") // Toutes les heures
	@Transactional
	public void cleanExpiredTokens() {
		blackListedTokenRepository.deleteByExpiryDateBefore(Instant.now());
	}

	@Scheduled(cron = "0 0 9 * * ?") // Tous les jours à 9h
	public void checkPasswordExpiration() {
		LocalDateTime expirationThreshold = LocalDateTime.now().minusDays(90); // 3 mois
		List<User> users = userRepository.findByPasswordChangedAtBefore(expirationThreshold);

		users.forEach(user -> {
			emailService.sendPasswordExpirationWarning(
					user.getEmail(),
					"Votre mot de passe va expirer",
					"Votre mot de passe n'a pas été changé depuis plus de 90 jours."
			);
		});
	}

	@Scheduled(cron = "0 0 3 * * ?")
	@Transactional
	public void removeUnverifiedAccounts() {
		LocalDateTime threshold = LocalDateTime.now().minusDays(30);
		List<User> oldUnverified = userRepository.findAll()
				.stream()
				.filter(u -> !u.isEnabled() && u.getCreatedAt().isBefore(threshold))
				.collect(Collectors.toList());
		userRepository.deleteAll(oldUnverified);
	}

	@Scheduled(cron = "0 0 3 * * ?") // Tous les jours à 3h du matin
	public void cleanExpiredRefreshTokens() {
		refreshTokenService.cleanExpiredTokens();
	}
}
