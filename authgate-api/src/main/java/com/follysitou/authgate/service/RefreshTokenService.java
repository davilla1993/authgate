package com.follysitou.authgate.service;

import com.follysitou.authgate.exceptions.UnauthorizedException;
import com.follysitou.authgate.handlers.ErrorCodes;
import com.follysitou.authgate.models.RefreshToken;
import com.follysitou.authgate.models.User;
import com.follysitou.authgate.repository.RefreshTokenRepository;
import com.follysitou.authgate.repository.UserRepository;
import com.follysitou.authgate.utils.TokenUtils;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    @Value("${app.jwt.refresh-expiration}")
    private long refreshTokenExpirationMs;

    // Crée un nouveau refresh token et l'associe à l'utilisateur
    public RefreshToken createRefreshToken(User user) {
        String refreshToken = jwtService.generateRefreshToken(user);
        String tokenHash = TokenUtils.sha256(refreshToken);

        RefreshToken newToken = new RefreshToken();
        newToken.setTokenHash(tokenHash);
        newToken.setUser(user);
        newToken.setExpiryDate(Instant.now().plusMillis(refreshTokenExpirationMs));

        return refreshTokenRepository.save(newToken);
    }

    // Valide et retourne le token s'il est valide
    public RefreshToken verifyRefreshToken(String token) {
        String tokenHash = TokenUtils.sha256(token);
        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new UnauthorizedException("Invalid refresh token", ErrorCodes.TOKEN_INVALID));

        if (!refreshToken.isValid()) {
            throw new UnauthorizedException("Refresh token revoked or expired", ErrorCodes.REFRESH_TOKEN_INVALID);
        }

        return refreshToken;
    }

    // Révoque tous les tokens de l'utilisateur (pour logout global)
    public void revokeAllUserTokens(User user) {
        List<RefreshToken> validTokens = refreshTokenRepository.findByUserAndRevokedFalse(user);
        validTokens.forEach(token -> token.setRevoked(true));
        refreshTokenRepository.saveAll(validTokens);
    }

    // Nettoie les tokens expirés (à appeler via un Scheduled)
    @Transactional
    public void cleanExpiredTokens() {
        refreshTokenRepository.deleteByExpiryDateBefore(Instant.now());
    }

    public void revokeRefreshToken(String token) {
        refreshTokenRepository.findByTokenHash(TokenUtils.sha256(token))
                .ifPresent(t -> {
                    t.setRevoked(true);
                    refreshTokenRepository.save(t);
                });
    }
}
