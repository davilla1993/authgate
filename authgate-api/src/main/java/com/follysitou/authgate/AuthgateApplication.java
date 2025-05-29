package com.follysitou.authgate;

import com.follysitou.authgate.repository.BlackListedTokenRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Instant;

@SpringBootApplication
@RequiredArgsConstructor
public class AuthgateApplication {

	private final BlackListedTokenRepository blackListedTokenRepository;

	public static void main(String[] args) {
		SpringApplication.run(AuthgateApplication.class, args);
	}

	@Scheduled(cron = "0 0 * * * *") // Toutes les heures
	@Transactional
	public void cleanExpiredTokens() {
		blackListedTokenRepository.deleteByExpiryDateBefore(Instant.now());
	}

}
