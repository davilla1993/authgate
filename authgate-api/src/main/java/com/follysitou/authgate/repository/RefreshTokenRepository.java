package com.follysitou.authgate.repository;

import com.follysitou.authgate.models.RefreshToken;
import com.follysitou.authgate.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    void deleteByExpiryDateBefore(Instant now);

    List<RefreshToken> findByUserAndRevokedFalse(User user);
}
