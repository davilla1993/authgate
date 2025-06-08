package com.follysitou.authgate.audit;

import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.PrePersist;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class Auditable {

    @Column(name = "public_id",
            nullable = false,
            unique = true,
            updatable = false)
    private UUID publicId;

    @CreatedBy
    @Column(name = "created_by",
            updatable = false)
    protected String createdBy;

    @CreatedDate
    @Column(name = "created_at",
            updatable = false)
    protected Instant createdAt;

    @LastModifiedBy
    @Column(name = "updated_by")
    protected String updatedBy;

    @LastModifiedDate
    @Column(name = "updated_at")
    protected Instant updatedAt;

    @Column(name = "deleted_by")
    protected String deletedBy;

    @Column(name = "deleted_at")
    protected Instant deletedAt;

    @Column(name = "deleted")
    private boolean deleted;

    @PrePersist
    public void generatePublicId() {
        if (publicId == null) {
            publicId = UUID.randomUUID();
        }
    }
}
