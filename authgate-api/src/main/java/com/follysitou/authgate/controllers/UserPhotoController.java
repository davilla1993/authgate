package com.follysitou.authgate.controllers;

import com.follysitou.authgate.exceptions.EntityNotFoundException;
import com.follysitou.authgate.models.User;
import com.follysitou.authgate.repository.UserRepository;
import com.follysitou.authgate.service.FileStorageService;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/users/{userId}/photo")
@RequiredArgsConstructor
public class UserPhotoController {

    private final UserRepository userRepository;
    private final FileStorageService fileStorageService;

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasAuthority('user:update') or #userId == principal.id")
    public ResponseEntity<String> uploadPhoto(@PathVariable Long userId, @RequestParam("file") MultipartFile file) {

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        if (user.getPhotoUrl() != null) {
            fileStorageService.deleteFile(user.getPhotoUrl());
        }

        String filename = fileStorageService.storeFile(file, userId.toString());
        user.setPhotoUrl(filename);
        userRepository.save(user);

        return ResponseEntity.ok("Photo updated successfully");
    }

    @GetMapping
    public ResponseEntity<Resource> getPhoto(@PathVariable Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        if (user.getPhotoUrl() == null) {
            return ResponseEntity.notFound().build();
        }

        Resource resource = fileStorageService.loadFileAsResource(user.getPhotoUrl());

        return ResponseEntity.ok()
                .contentType(MediaType.IMAGE_JPEG)
                .body(resource);
    }

    @DeleteMapping
    @PreAuthorize("hasAuthority('user:update') or #userId == principal.id")
    public ResponseEntity<String> deletePhoto(@PathVariable Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        if (user.getPhotoUrl() != null) {
            fileStorageService.deleteFile(user.getPhotoUrl());
            user.setPhotoUrl(null);
            userRepository.save(user);
            return ResponseEntity.ok("Photo deleted successfully");
        }

        return ResponseEntity.badRequest().body("No photos to delete");
    }
}
