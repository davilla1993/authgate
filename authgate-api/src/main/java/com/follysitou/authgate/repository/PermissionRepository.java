package com.follysitou.authgate.repository;

import com.follysitou.authgate.models.Permission;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, Long> {

    boolean existsByNameIgnoreCase(String name);

    @Override
    Optional<Permission>  findById(@NonNull Long id);

    @Cacheable("permissions")
    Optional<Permission> findByName(String name);

    boolean existsByName(String name);
}
