package com.follysitou.authgate.controllers;

import com.follysitou.authgate.models.User;
import com.follysitou.authgate.repository.UserRepository;
import com.follysitou.authgate.service.FileStorageService;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/users/{userId}/photo")
@RequiredArgsConstructor
public class UserPhotoController {

    private final UserRepository userRepository;
    private final FileStorageService fileStorageService;

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> uploadPhoto(
            @PathVariable Long userId,
            @RequestParam("file") MultipartFile file) {

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));

        // Supprime l'ancienne photo si elle existe
        if (user.getPhotoUrl() != null) {
            fileStorageService.deleteFile(user.getPhotoUrl());
        }

        String filename = fileStorageService.storeFile(file, userId.toString());
        user.setPhotoUrl(filename);
        userRepository.save(user);

        return ResponseEntity.ok("Photo mise à jour avec succès");
    }

    @GetMapping
    public ResponseEntity<Resource> getPhoto(@PathVariable Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));

        if (user.getPhotoUrl() == null) {
            return ResponseEntity.notFound().build();
        }

        Resource resource = fileStorageService.loadFileAsResource(user.getPhotoUrl());

        return ResponseEntity.ok()
                .contentType(MediaType.IMAGE_JPEG) // Adaptez selon le type réel
                .body(resource);
    }

    @DeleteMapping
    public ResponseEntity<String> deletePhoto(@PathVariable Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));

        if (user.getPhotoUrl() != null) {
            fileStorageService.deleteFile(user.getPhotoUrl());
            user.setPhotoUrl(null);
            userRepository.save(user);
            return ResponseEntity.ok("Photo supprimée avec succès");
        }

        return ResponseEntity.badRequest().body("Aucune photo à supprimer");
    }
}
