package com.follysitou.authgate.repository;

import com.follysitou.authgate.models.BlackListedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;

@Repository
public interface BlackListedTokenRepository extends JpaRepository<BlackListedToken, String> {
    boolean existsByToken(String token);

    @Modifying
    @Query("DELETE FROM BlackListedToken t WHERE t.expiryDate < :now")
    void deleteByExpiryDateBefore(@Param("now") Instant now);
}
