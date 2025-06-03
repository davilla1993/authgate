package com.follysitou.authgate.init;

import com.follysitou.authgate.models.Permission;
import com.follysitou.authgate.models.Role;
import com.follysitou.authgate.repository.PermissionRepository;
import com.follysitou.authgate.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
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

            // 1. Créer les permissions de base en gérant les doublons
            createPermissionIfNotExists("basic_access", "Accès basique à l'application");

            // 2. Liste des permissions dynamiques à créer
            Map<String, String> dynamicPermissions = getStringStringMap();

            // 4. Création des rôles
            createRoleIfNotExists("ROLE_USER", Set.of("basic_access"));
            createRoleIfNotExists("ROLE_ADMIN", new HashSet<>(dynamicPermissions.keySet()));

            log.info("Initialisation terminée avec succès");
        };
    }

    private Map<String, String> getStringStringMap() {
        Map<String, String> dynamicPermissions = Map.of(
                "USER_CREATE", "Créer un utilisateur",
                "USER_READ", "Lire les informations utilisateur",
                "USER_UPDATE", "Mettre à jour un utilisateur",
                "USER_DELETE", "Supprimer un utilisateur",
                "USER_LOCK", "Verrouiller un compte utilisateur",
                "USER_UNLOCK", "Déverrouiller un compte utilisateur",
                "ROLE_CREATE", "Créer un rôle",
                "ROLE_ASSIGN", "Assigner un rôle"
        );

        // 3. Création des permissions
        dynamicPermissions.forEach(this::createPermissionIfNotExists);
        return dynamicPermissions;
    }

    private void createPermissionIfNotExists(String name, String description) {
        if (!permissionRepo.existsByNameIgnoreCase(name)) {
            Permission p = new Permission();
            p.setName(name);
            p.setDescription(description);
            permissionRepo.saveAndFlush(p);

            log.info("Permission créée : {}", name);
        } else {
            log.info("Permission déjà existante : {}", name);
        }
    }

    private void createRoleIfNotExists(String roleName, Set<String> permissionNames) {
        if (!roleRepo.existsByName(roleName)) {
            Set<Permission> permissions = permissionNames.stream()
                    .map(name -> permissionRepo.findByNameIgnoreCase(name)
                            .orElseThrow(() -> new RuntimeException("Permission non trouvée: " + name)))
                    .collect(Collectors.toSet());

            Role role = new Role();
            role.setName(roleName);
            role.setDescription(roleName.equals("ROLE_ADMIN")
                    ? "Rôle administrateur avec tous les droits"
                    : "Rôle utilisateur de base");
            role.setPermissions(permissions);

            roleRepo.save(role);
            log.info("Rôle {} créé avec {} permissions", roleName, permissions.size());
        } else {
            log.info("Rôle déjà existant : {}", roleName);
        }
    }
}