package com.follysitou.authgate;

import com.follysitou.authgate.models.User;
import com.follysitou.authgate.repository.BlackListedTokenRepository;
import com.follysitou.authgate.repository.UserRepository;
import com.follysitou.authgate.service.EmailService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;

@SpringBootApplication
@RequiredArgsConstructor
public class AuthgateApplication {

	private final EmailService emailService;
	private final UserRepository userRepository;
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

}
