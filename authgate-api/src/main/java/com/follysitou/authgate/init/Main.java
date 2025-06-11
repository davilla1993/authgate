
package com.follysitou.authgate.init;

import com.follysitou.authgate.models.Permission;
import com.follysitou.authgate.models.Role;
import com.follysitou.authgate.models.User;
import com.follysitou.authgate.repository.PermissionRepository;
import com.follysitou.authgate.repository.RoleRepository;
import com.follysitou.authgate.service.DynamicPermissionGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class Main {

    private final RoleRepository roleRepo;
    private final PermissionRepository permissionRepo;

    @Bean
    @Transactional
    public CommandLineRunner initPermissionsAndRoles() {
        return args -> {
            log.info("Début de l'initialisation des permissions et rôles...");

            // 1. Permissions statiques (utilisées dans @PreAuthorize)
            Map<String, String> staticPermissions = Map.of(
                    "user:self:read", "Lire son propre profil",
                    "user:self:update", "Modifier son propre profil",
                    "user:self:delete", "Supprimer son propre profil",
                    "basic_access", "Accès basique à l'application"
            );

            // 2. Permissions dynamiques ADMIN
            Map<String, String> adminPermissions = DynamicPermissionGenerator
                    .generatePermissionMapFor(User.class, "admin", "Gestion des utilisateurs (admin)");

            // 3. Fusion des permissions
            Map<String, String> allPermissions = new HashMap<>();
            allPermissions.putAll(staticPermissions);
            allPermissions.putAll(adminPermissions);

            // 4. Création des permissions en base (format DB)
            allPermissions.forEach(this::createPermissionIfNotExists);

            // 5. Création des rôles
            createRoleIfNotExists("ROLE_USER", Set.of(
                    "basic_access",
                    "user:self:read",
                    "user:self:update",
                    "user:self:delete"
            ));

            createRoleIfNotExists("ROLE_ADMIN", allPermissions.keySet());

            log.info("Initialisation terminée avec succès");
        };
    }

    private void createPermissionIfNotExists(String permissionKey, String description) {
        String dbPermissionName = DynamicPermissionGenerator.toDatabaseFormat(permissionKey);

        if (!permissionRepo.existsByNameIgnoreCase(dbPermissionName)) {
            Permission p = new Permission();
            p.setName(dbPermissionName);
            p.setDescription(description);
            p.setCreatedBy("carlogbossou93@gmail.com");
            permissionRepo.saveAndFlush(p);

            log.info("Permission créée : {}", dbPermissionName);
        } else {
            log.info("Permission déjà existante : {}", dbPermissionName);
        }
    }

    private void createRoleIfNotExists(String roleName, Set<String> permissionKeys) {
        if (!roleRepo.existsByName(roleName)) {
            Set<Permission> permissions = permissionKeys.stream()
                    .map(DynamicPermissionGenerator::toDatabaseFormat)
                    .map(name -> permissionRepo.findByNameIgnoreCase(name)
                            .orElseThrow(() -> {
                                log.error("Permission introuvable pour le rôle {} : {}", roleName, name);
                                return new RuntimeException("Permission non trouvée: " + name);
                            }))
                    .collect(Collectors.toSet());

            Role role = new Role();
            role.setName(roleName);
            role.setDescription(roleName.equals("ROLE_ADMIN")
                    ? "Rôle administrateur avec tous les droits"
                    : "Rôle utilisateur de base");
            role.setPermissions(permissions);
            role.setCreatedBy("carlogbossou93@gmail.com");
            roleRepo.save(role);

            log.info("Rôle {} créé avec {} permissions", roleName, permissions.size());
        } else {
            log.info("Rôle déjà existant : {}", roleName);
        }
    }
}


