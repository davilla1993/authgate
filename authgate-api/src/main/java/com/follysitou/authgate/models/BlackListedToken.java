package com.follysitou.authgate.models;

import com.follysitou.authgate.utils.TokenUtils;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.Instant;

@Entity
@Getter
@Table(name = "blacklisted_tokens")
public class BlackListedToken {

    @Id
    private String tokenHash;

    private Instant expiryDate;


    public BlackListedToken() {
    }

    public BlackListedToken(String token, Instant expiryDate) {
        this.tokenHash = TokenUtils.sha256(token);
        this.expiryDate = expiryDate;
    }

}
