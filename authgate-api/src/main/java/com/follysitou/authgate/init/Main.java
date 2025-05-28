package com.follysitou.authgate.init;

import com.follysitou.authgate.models.Permission;
import com.follysitou.authgate.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;

@RequiredArgsConstructor
public class Main {

    private final PermissionRepository permissionRepository;

    @Bean
    public CommandLineRunner initPermissions(PermissionRepository permissionRepo) {
        return args -> {
            // Permissions CRUD de base
            String[][] permissionsData = {
                    {"CREATE_USER", "Créer un utilisateur"},
                    {"READ_USER", "Lire les utilisateurs"},
                    {"UPDATE_USER", "Modifier un utilisateur"},
                    {"DELETE_USER", "Supprimer un utilisateur"},
                    // Ajoutez d'autres entités (product, order, etc.)
            };

            for (String[] data : permissionsData) {
                if (!permissionRepo.existsByName(data[0])) {
                    Permission p = new Permission();
                    p.setName(data[0]);
                    p.setDescription(data[1]);
                    permissionRepo.save(p);
                }
            }
        };
    }
}
