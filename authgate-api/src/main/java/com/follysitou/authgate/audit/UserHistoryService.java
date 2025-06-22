package com.follysitou.authgate.audit;

import com.follysitou.authgate.models.User;
import org.hibernate.envers.AuditReader;
import org.hibernate.envers.AuditReaderFactory;
import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserHistoryService {

    private final EntityManager entityManager;

    public UserHistoryService(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    public List<?> getUserRevisions(Long userId) {
        AuditReader auditReader = AuditReaderFactory.get(entityManager);
        // Récupère toutes les révisions (versions) pour un utilisateur donné
        return auditReader.createQuery()
                .forRevisionsOfEntity(User.class, false, true)
                .add(org.hibernate.envers.query.AuditEntity.id().eq(userId))
                .getResultList();
    }

    public User getUserAtRevision(Long userId, Number revisionNumber) {
        AuditReader auditReader = AuditReaderFactory.get(entityManager);
        // Récupère l'utilisateur à une révision spécifique
        return auditReader.find(User.class, userId, revisionNumber);
    }
}
