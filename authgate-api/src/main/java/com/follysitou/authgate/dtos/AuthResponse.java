package com.follysitou.authgate.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthResponse {

    private String accessToken;
    private String refreshToken;
    private String message;
    private boolean requiresVerification;

    public AuthResponse(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;

    }

    public AuthResponse(String token) {
        this.accessToken = token;
        this.requiresVerification = false;
    }
    public AuthResponse(String message, boolean requiresVerification) {
        this.message = message;
        this.requiresVerification = requiresVerification;
    }
}
