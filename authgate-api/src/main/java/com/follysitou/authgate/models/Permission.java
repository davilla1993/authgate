package com.follysitou.authgate.models;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "permissions")
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String name;

    private String description;

    @PrePersist
    public void normalizeName() {
        this.name = this.name.toUpperCase().replace(":", "_");
        // Convertit "user:lock" en "USER_LOCK" pour compatibilité
    }
}
