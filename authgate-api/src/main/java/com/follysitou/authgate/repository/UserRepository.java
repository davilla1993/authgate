package com.follysitou.authgate.repository;

import com.follysitou.authgate.dtos.user.UserResponseDto;
import com.follysitou.authgate.models.Role;
import com.follysitou.authgate.models.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);
    boolean existsByEmail(String email);
    boolean existsByRolesContaining(Role role);

    Page<User> findByOnlineTrue(Pageable pageable);


    Optional<User> findByResetPasswordToken(String token);
    List<User> findByPasswordChangedAtBefore(LocalDateTime date);

    long countByEnabledTrue();
    long countByAccountNonLockedFalse();
    long countByCreatedAtAfter(LocalDateTime date);
    long countByOnlineTrue();

    @Query("SELECT u FROM User u WHERE u.accountNonLocked = false OR u.manualLockTime IS NOT NULL")
    Page<UserResponseDto> findAllLockedAccounts(Pageable pageable);

    Page<User> findByEnabledTrue(Pageable pageable);
    Page<User> findByEnabledFalse(Pageable pageable);

    @Query("SELECT u FROM User u WHERE " +
            "LOWER(u.firstName) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
            "LOWER(u.lastName) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
            "LOWER(u.email) LIKE LOWER(CONCAT('%', :keyword, '%'))")
    Page<User> searchByKeyword(@Param("keyword") String keyword, Pageable pageable);


    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.lastActivity = :activity, u.online = :online WHERE u.email = :email")
    void updateLastActivityAndOnline(@Param("email") String email,
                                     @Param("activity") Instant activity,
                                     @Param("online") boolean online);


    @Modifying
    @Query("UPDATE User u SET u.online = false WHERE u.lastActivity < :threshold AND u.online = true")
    void markUsersOfflineBefore(@Param("threshold") Instant threshold);


}
