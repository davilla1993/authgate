package com.follysitou.authgate.models;

import com.follysitou.authgate.utils.TokenUtils;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Getter
@Table(name = "blacklisted_tokens")
public class BlackListedToken {

    @Id
    @Column(updatable = false, nullable = false, length = 150)
    private String tokenHash;

    private Instant expiryDate;


    public BlackListedToken() {
    }

    public BlackListedToken(String token, Instant expiryDate) {
        this.tokenHash = TokenUtils.sha256(token);
        this.expiryDate = expiryDate;
    }
}
