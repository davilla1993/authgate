package com.follysitou.authgate.repository;

import com.follysitou.authgate.models.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
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

    long countByEnabledTrue();
    long countByAccountNonLockedFalse();
    long countByCreatedAtAfter(LocalDateTime date);

    @Query("SELECT u FROM User u WHERE u.accountNonLocked = false OR u.manualLockTime IS NOT NULL")
    List<User> findAllLockedAccounts();

    Page<User> findByEnabledTrue(Pageable pageable);
    Page<User> findByEnabledFalse(Pageable pageable);
    List<User> findByLastLoginAttemptAfter(LocalDateTime time);

    @Query("SELECT u FROM User u WHERE " +
            "LOWER(u.firstName) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
            "LOWER(u.lastName) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
            "LOWER(u.email) LIKE LOWER(CONCAT('%', :keyword, '%'))")
    Page<User> searchByKeyword(@Param("keyword") String keyword, Pageable pageable);
}
