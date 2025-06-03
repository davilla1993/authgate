package com.follysitou.authgate.repository;

import com.follysitou.authgate.models.Permission;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, Long> {

    boolean existsByNameIgnoreCase(String name);

    @Override
    @Cacheable("permissions")
    Optional<Permission> findById(Long id);

    @Cacheable("permissions")
    Optional<Permission> findByNameIgnoreCase(String name);



}
