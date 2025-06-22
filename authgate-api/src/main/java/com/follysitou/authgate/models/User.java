package com.follysitou.authgate.models;

import com.follysitou.authgate.audit.Auditable;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.envers.Audited;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Entity
@Getter
@Setter
@Slf4j
@NoArgsConstructor
@AllArgsConstructor
@Audited
@Table(name = "users")
public class User extends Auditable implements UserDetails {

    private static final int MAX_FAILED_ATTEMPTS = 3;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String firstName;

    private String lastName;

    @Email
    @Column(unique = true)
    private String email;

    private String password;

    @Column(name = "photo_url", length = 255)
    private String photoUrl;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    private LocalDateTime lockTime;
    private String lockReason;
    private LocalDateTime manualLockTime;
    private String lockedBy; // Email de l'admin qui a verrouillé

    private LocalDateTime passwordChangedAt;

    private Instant lastActivity;

    private boolean online;

    private int failedAttempts;

    private boolean enabled = true;

    private boolean accountNonExpired = true;

    private boolean accountNonLocked = true;

    private boolean credentialsNonExpired = true;

    private String verificationCode;

    private LocalDateTime verificationCodeExpiry;

    private String resetPasswordToken;

    private LocalDateTime resetPasswordTokenExpiry;

    public void recordPasswordChange() {
        this.passwordChangedAt = LocalDateTime.now();
    }

    public User(String firstName, String lastName, String email, String password) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.password = password;
        this.enabled = false;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

     return this.roles.stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(permission -> new SimpleGrantedAuthority(
                        permission.getName().toLowerCase().replace("_", ":")
                ))
             .collect(Collectors.toList());
    }

    public boolean incrementFailedAttempts() {
        this.failedAttempts++;
        log.info(">>> Tentative échouée pour {}, tentative n°{}", this.email, this.failedAttempts);

        if (this.failedAttempts >= MAX_FAILED_ATTEMPTS) {
            this.lockAccount();
            log.warn("Compte verrouillé pour email: {}", this.email);

            return true;
        }
        return false;
    }

    public void lockAccount() {
        this.accountNonLocked = false;
        this.lockTime = LocalDateTime.now();
    }

    public void manualLock(String reason, String lockedBy) {
        this.accountNonLocked = false;
        this.lockReason = reason;
        this.manualLockTime = LocalDateTime.now();
        this.lockedBy = lockedBy;
    }

    public void unlockAccount() {
        this.accountNonLocked = true;
        this.failedAttempts = 0;
        this.lockTime = null;
    }

    public boolean isAccountLocked() {
        return !this.accountNonLocked;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

}

