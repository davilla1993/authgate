package com.follysitou.authgate.models;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;

import java.time.Instant;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "blacklisted_tokens")
public class BlackListedToken {

    @Id
    private String token;

    private Instant expiryDate;

}
