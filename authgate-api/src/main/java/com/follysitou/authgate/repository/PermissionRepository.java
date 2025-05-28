package com.follysitou.authgate.repository;

import com.follysitou.authgate.models.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, Long> {

    boolean existsByName(String name);

    Optional<Permission> findByName(String name);
}
