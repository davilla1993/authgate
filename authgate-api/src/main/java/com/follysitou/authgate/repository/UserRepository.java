package com.follysitou.authgate.repository;

import com.follysitou.authgate.models.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    Optional<User> findByResetPasswordToken(String token);

    List<User> findByPasswordChangedAtBefore(LocalDateTime date);

    List<User> findByAccountNonLockedFalse();

    Page<User> findByAccountNonLockedFalse(Pageable pageable);

    @Query("SELECT u FROM User u WHERE u.accountNonLocked = false OR u.manualLockTime IS NOT NULL")
    List<User> findAllLockedAccounts();
}
