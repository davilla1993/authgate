package com.follysitou.authgate;

import com.follysitou.authgate.repository.BlackListedTokenRepository;
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

	@Scheduled(cron = "0 0 * * * *") // chaque heure
	public void cleanExpiredTokens() {
		Instant now = Instant.now();
		blackListedTokenRepository.deleteAll(
				blackListedTokenRepository.findAll().stream()
						.filter(t -> t.getExpiryDate().isBefore(now))
						.toList()
		);
	}

}
