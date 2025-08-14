package com.follysitou.authgate.service;

import com.follysitou.authgate.exceptions.UnauthorizedException;
import com.follysitou.authgate.handlers.ErrorCodes;
import com.follysitou.authgate.models.RefreshToken;
import com.follysitou.authgate.models.User;
import com.follysitou.authgate.repository.BlackListedTokenRepository;
import com.follysitou.authgate.repository.RefreshTokenRepository;
import com.follysitou.authgate.repository.UserRepository;
import com.follysitou.authgate.utils.TokenUtils;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final BlackListedTokenRepository blackListedTokenRepository;

    @Value("${app.jwt.refresh-expiration}")
    private long refreshTokenExpirationMs;

    @Transactional
    public String createRefreshToken(User user) {

        // Révoquer tous les tokens existants pour cet utilisateur
        revokeAllUserTokens(user);

        // Générer un nouveau refresh token
        String refreshToken = jwtService.generateRefreshToken(user);
        String tokenHash = TokenUtils.sha256(refreshToken);

        RefreshToken newToken = new RefreshToken();
        newToken.setTokenHash(tokenHash);
        newToken.setUser(user);
        newToken.setExpiryDate(Instant.now().plusMillis(refreshTokenExpirationMs));
        newToken.setRevoked(false);
        refreshTokenRepository.save(newToken);

        return refreshToken;

    }

    @Transactional
    public RefreshToken verifyRefreshToken(String token) {

        // 1. Vérifier la validité JWT
        if(!jwtService.isTokenValid(token)) {
            log.error("JWT validation failed for token");
            throw new UnauthorizedException("Invalid refresh token ", ErrorCodes.TOKEN_INVALID);
        }

        // 2. Vérifier dans la base de données
        String tokenHash = TokenUtils.sha256(token);
        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> {
                    return new UnauthorizedException("Invalid refresh token", ErrorCodes.TOKEN_INVALID);
                });

        // 3. Vérifier s'il est révoqué ou expiré
        if (refreshToken.isRevoked()) {
            log.error("Refresh token was revoked");
            throw new UnauthorizedException("Refresh token was revoked", ErrorCodes.TOKEN_BLACKLISTED);
        }

        if (refreshToken.getExpiryDate().isBefore(Instant.now())) {
            log.error("Refresh token expired");
            throw new UnauthorizedException("Refresh token expired", ErrorCodes.TOKEN_EXPIRED);
        }

        log.info("Refresh token successfully verified for user: {}", refreshToken.getUser().getEmail());
        return refreshToken;
    }

    @Transactional
    public void revokeRefreshToken(String token) {
        String tokenHash = TokenUtils.sha256(token);
        refreshTokenRepository.findByTokenHash(tokenHash)
                .ifPresent(t -> {
                    t.setRevoked(true);
                    refreshTokenRepository.save(t);
                });
    }

   @Transactional
    public void revokeAllUserTokens(User user) {
        List<RefreshToken> validTokens = refreshTokenRepository.findByUserAndRevokedFalse(user);
       if (!validTokens.isEmpty()) {
           validTokens.forEach(token -> token.setRevoked(true));
           refreshTokenRepository.saveAll(validTokens);
           log.info("All refresh tokens revoked for user: {}", user.getEmail());
       }
    }

    // Nettoie les tokens expirés (à appeler via un Scheduled)
    @Transactional
    public void cleanExpiredTokens() {
        refreshTokenRepository.deleteByExpiryDateBefore(Instant.now());
        log.info("Expired refresh tokens cleaned");
    }

}
