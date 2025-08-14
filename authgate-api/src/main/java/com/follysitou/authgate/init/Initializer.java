
package com.follysitou.authgate.init;

import com.follysitou.authgate.models.Permission;
import com.follysitou.authgate.models.Role;
import com.follysitou.authgate.models.User;
import com.follysitou.authgate.repository.PermissionRepository;
import com.follysitou.authgate.repository.RoleRepository;
import com.follysitou.authgate.repository.UserRepository;
import com.follysitou.authgate.service.DynamicPermissionGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class Initializer {

    private final RoleRepository roleRepo;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PermissionRepository permissionRepo;

    @Bean
    @Transactional // Ensure transactional execution for data initialization
    public CommandLineRunner initPermissionsAndRoles() {
        return args -> {
            log.info("Starting data initialization...");

            // 1. Permissions statiques pour l'ADMIN et l'ACCOUNT_MANAGER
            Map<String, String> staticPermissionsForAdminAndAccountManager = Map.of(
                    "admin:access", "Accès à l'interface d'administration",
                    "admin:self:read", "Lire son propre profil",
                    "admin:self:update", "Modifier son propre profil",
                    "admin:self:delete", "Supprimer son propre profil",
                    "admin:user:account-control", "Contrôler totalement les comptes utilisateur",
                    "admin:token:revoke", "Révoquer les tokens utilisateur", // Added based on AuthGateAPI.txt
                    "admin:system:read", "Lire les informations système", // Added based on AuthGateAPI.txt
                    "admin:role:assign", "Assigner les rôles aux utilisateurs", // Added based on AuthGateAPI.txt
                    "admin:role:revoke", "Révoquer les rôles aux utilisateurs",
                    "basic:access", "Accès basique à l'application" // Keep if needed for general access
            );


            // 1. Permissions statiques pour le USER
            Map<String, String> staticPermissionsForUser = Map.of(
                    "user:access", "Accès à l'interface utilisateur",
                    "user:self:read", "Lire son propre profil",
                    "user:self:update", "Modifier son propre profil",
                    "user:self:delete", "Supprimer son propre profil",
                    "user:update", "Mettre à jour les informations de l'utilisateur", // Added based on AuthGateAPI.txt
                    "basic:access", "Accès basique à l'application"
            );

            // 2. Permissions dynamiques ADMIN et ACCOUNT_MANAGER (sur les entités Role et User)
            Map<String, String> dynamicPermissionsForAdminAndAccountManager = new HashMap<>();
            dynamicPermissionsForAdminAndAccountManager.putAll(DynamicPermissionGenerator
                    .generatePermissionMapFor(User.class, "admin", "Gestion des utilisateurs (admin)"));
            dynamicPermissionsForAdminAndAccountManager.putAll(DynamicPermissionGenerator
                    .generatePermissionMapFor(Role.class, "admin", "Gestion des rôles (admin)"));


            // 3. Fusion des permissions pour ADMIN et ACCOUNT_MANAGER
            Map<String, String> allPermissionsForAdminAndAccountManager = new HashMap<>();
            allPermissionsForAdminAndAccountManager.putAll(staticPermissionsForAdminAndAccountManager);
            allPermissionsForAdminAndAccountManager.putAll(dynamicPermissionsForAdminAndAccountManager);


            // 4. Création de toutes les permissions uniques en base (format DB)
            Set<String> allUniquePermissionKeys = new HashSet<>();
            allUniquePermissionKeys.addAll(allPermissionsForAdminAndAccountManager.keySet());
            allUniquePermissionKeys.addAll(staticPermissionsForUser.keySet());

            allUniquePermissionKeys.forEach(permissionKey -> {
                String description = allPermissionsForAdminAndAccountManager.getOrDefault(permissionKey,
                        staticPermissionsForUser.getOrDefault(permissionKey, "Permission générique"));
                createPermissionIfNotExists(permissionKey, description);
            });


            // 5. Création des rôles et association des permissions
            // Note: Permissions must exist in DB before being assigned to roles
            createRoleIfNotExists("ROLE_USER", staticPermissionsForUser.keySet());
            createRoleIfNotExists("ROLE_ADMIN", allPermissionsForAdminAndAccountManager.keySet());
            // Create ROLE_ACCOUNT_MANAGER with the exact same permissions as ROLE_ADMIN
            createRoleIfNotExists("ROLE_ACCOUNT_MANAGER", allPermissionsForAdminAndAccountManager.keySet());


            // 6. Création de l'utilisateur ADMIN par défaut
            createAdminUserIfNotExists();

            log.info("Initialisation terminée avec succès");
        };
    }
    
    private void createPermissionIfNotExists(String permissionKey, String description) {
      //  String dbPermissionName = DynamicPermissionGenerator.toDatabaseFormat(permissionKey);

        if (!permissionRepo.existsByName(permissionKey)) {
            Permission p = new Permission();
            p.setName(permissionKey);
            p.setDescription(description);
            p.setCreatedBy("Auto-generated");
            permissionRepo.saveAndFlush(p);

            log.info("Permission créée : {}", permissionKey);
        } else {
            log.info("Permission déjà existante : {}", permissionKey);
        }
    }

    private void createRoleIfNotExists(String roleName, Set<String> permissionKeys) {
        if (!roleRepo.existsByName(roleName)) {
            Set<Permission> permissions = permissionKeys.stream()
                    .map(name -> {
                        Optional<Permission> permissionOpt = permissionRepo.findByName(name);
                        if (permissionOpt.isEmpty()) {
                            log.error("Permission introuvable pour le rôle {} : {}", roleName, name);
                            throw new RuntimeException("Permission non trouvée: " + name);
                        }
                        return permissionOpt.get();
                    })
                    .collect(Collectors.toSet());


            Role role = new Role();
            role.setName(roleName);
            role.setDescription(
                    switch (roleName) {
                        case "ROLE_ADMIN" -> "Rôle administrateur avec tous les droits";
                        case "ROLE_ACCOUNT_MANAGER" -> "Rôle de gestionnaire de comptes avec les droits d'administration sur les utilisateurs";
                        default -> "Rôle utilisateur de base"; // Covers ROLE_USER and any future default
                    }
            );
            role.setPermissions(permissions);
            role.setCreatedBy("Auto-generated"); // User information: `carlogbossou93@gmail.com`
            roleRepo.save(role);

            log.info("Rôle {} créé avec {} permissions", roleName, permissions.size());
        } else {
            log.info("Rôle déjà existant : {}", roleName);
        }
    }

    private void createAdminUserIfNotExists() {
        String email = "javaprogrammer1993@gmail.com"; // Your default admin email

        if (!userRepository.existsByEmail(email)) {
            User user = new User();
            user.setEmail(email);
            user.setPassword(passwordEncoder.encode("Password@1234")); // Default password
            user.setFirstName("Java");
            user.setLastName("Programmer");
            user.setEnabled(true);
            user.setAccountNonLocked(true); // Ensure admin is not locked by default
            user.setCreatedBy("system@authgate.com"); // User information: `carlogbossou93@gmail.com`
            user.setCreatedAt(Instant.now()); // Set creation timestamp

            Role adminRole = roleRepo.findByName("ROLE_ADMIN")
                    .orElseThrow(() -> new RuntimeException("ROLE_ADMIN introuvable. " +
                            "Assurez-vous que les rôles sont créés avant les utilisateurs."));

            user.setRoles(Set.of(adminRole));
            userRepository.save(user);

            log.info("Utilisateur ADMIN créé avec succès : {}", email);
        } else {
            log.info("Utilisateur ADMIN déjà existant : {}", email);
        }
    }
}


