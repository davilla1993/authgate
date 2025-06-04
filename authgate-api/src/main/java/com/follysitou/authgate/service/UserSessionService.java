package com.follysitou.authgate.service;

import com.follysitou.authgate.models.RefreshToken;
import com.follysitou.authgate.repository.BlackListedTokenRepository;
import com.follysitou.authgate.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserSessionService {

    private final BlackListedTokenRepository blackListedTokenRepository;
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional
    public void invalidateAllSessions(Long userId) {

        // 1. Invalider tous les refresh tokens
        List<RefreshToken> refreshTokens = refreshTokenRepository.findByUserId(userId);
        refreshTokens.forEach(token -> token.setRevoked(true));
        refreshTokenRepository.saveAll(refreshTokens);

    }
}