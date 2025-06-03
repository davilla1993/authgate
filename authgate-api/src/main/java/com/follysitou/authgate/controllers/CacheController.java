package com.follysitou.authgate.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/cache")
public class CacheController {

    @Autowired
    private CacheManager cacheManager;

    @GetMapping("/stats")
    public Map<String, String> getCacheStats() {
        return cacheManager.getCacheNames().stream()
                .collect(Collectors.toMap(
                        name -> name,
                        name -> Objects.requireNonNull(
                                cacheManager.getCache(name))
                                    .getNativeCache()
                                        .toString()
                ));
    }
}
