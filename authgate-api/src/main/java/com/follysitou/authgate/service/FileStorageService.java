package com.follysitou.authgate.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Objects;

@Service
public class FileStorageService {
    @Value("${app.file.upload-dir}")
    private String uploadDir;

    public String storeFile(MultipartFile file, String userId) {
        try {
            Path uploadPath = Paths.get(uploadDir).toAbsolutePath().normalize();

            // Crée le répertoire si inexistant
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath);
            }

            // Génère un nom de fichier unique
            String filename = String.format("%s_%d_%s",
                    userId,
                    System.currentTimeMillis(),
                    StringUtils.cleanPath(Objects.requireNonNull(file.getOriginalFilename())));

            // Stocke le fichier
            Path targetPath = uploadPath.resolve(filename);
            Files.copy(file.getInputStream(), targetPath, StandardCopyOption.REPLACE_EXISTING);

            return filename;
        } catch (IOException e) {
            throw new RuntimeException("Échec du stockage du fichier", e);
        }
    }

    public void deleteFile(String filename) {
        try {
            Path filePath = Paths.get(uploadDir).resolve(filename).normalize();
            Files.deleteIfExists(filePath);
        } catch (IOException e) {
            throw new RuntimeException("Échec de la suppression du fichier", e);
        }
    }

    public Resource loadFileAsResource(String filename) {
        try {
            Path filePath = Paths.get(uploadDir).resolve(filename).normalize();
            Resource resource = new UrlResource(filePath.toUri());

            if (resource.exists() && resource.isReadable()) {
                return resource;
            } else {
                throw new RuntimeException("Fichier non trouvé ou illisible");
            }
        } catch (IOException e) {
            throw new RuntimeException("Échec du chargement du fichier", e);
        }
    }
}
