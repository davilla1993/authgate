package com.follysitou.authgate.service;

import com.follysitou.authgate.exceptions.BusinessException;
import com.follysitou.authgate.exceptions.EntityNotFoundException;
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
import java.util.Set;

@Service
public class FileStorageService {

    @Value("${app.file.upload-dir}")
    private String uploadDir;

    private static final Set<String> ALLOWED_CONTENT_TYPES = Set.of(
            "image/jpeg", "image/png", "image/jpg"
    );

    private static final long MAX_FILE_SIZE = 2 * 1024 * 1024; // 2 MB

    public String storeFile(MultipartFile file, String userId) {
        try {
            // 1. Vérifie le type MIME
            String contentType = file.getContentType();
            if (!ALLOWED_CONTENT_TYPES.contains(contentType)) {
                throw new BusinessException("Unsupported file type: " + contentType);
            }

            // 2. Vérifie la taille
            if (file.getSize() > MAX_FILE_SIZE) {
                throw new BusinessException("File too large. Max size: 2MB");
            }

            // 3. Nettoie et construit le nom du fichier
            String originalFilename = StringUtils.cleanPath(Objects.requireNonNull(file.getOriginalFilename()));
            String extension = getExtension(originalFilename);
            String filename = String.format("%s_%d.%s", userId, System.currentTimeMillis(), extension);

            // 4. Crée le répertoire si inexistant
            Path uploadPath = Paths.get(uploadDir).toAbsolutePath().normalize();
            Files.createDirectories(uploadPath);

            // 5. Enregistre le fichier
            Path targetPath = uploadPath.resolve(filename);
            Files.copy(file.getInputStream(), targetPath, StandardCopyOption.REPLACE_EXISTING);

            return filename;
        } catch (IOException e) {
            throw new BusinessException("Failed to store file: " + e.getMessage());
        }
    }

    private String getExtension(String filename) {
        int dotIndex = filename.lastIndexOf('.');
        if (dotIndex == -1 || dotIndex == filename.length() - 1) {
            throw new BusinessException("Invalid file name or missing extension");
        }
        return filename.substring(dotIndex + 1).toLowerCase();
    }

    public void deleteFile(String filename) {
        try {
            Path filePath = Paths.get(uploadDir).resolve(filename).normalize();
            Files.deleteIfExists(filePath);
        } catch (IOException e) {
            throw new BusinessException("Failed to delete file: " + e.getMessage());
        }
    }

    public Resource loadFileAsResource(String filename) {
        try {
            Path filePath = Paths.get(uploadDir).resolve(filename).normalize();
            Resource resource = new UrlResource(filePath.toUri());

            if (resource.exists() && resource.isReadable()) {
                return resource;
            } else {
                throw new EntityNotFoundException("File not found or unreadable");
            }
        } catch (IOException e) {
            throw new BusinessException("Failed to load file: " + e.getMessage());
        }
    }
}
