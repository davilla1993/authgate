package com.follysitou.authgate.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthResponse {

    private String token;
    private String type = "Bearer";
    private String email;
    private String firstName;
    private String lastName;
    private boolean requiresVerification = false;

    public AuthResponse(String token, String email, String firstName, String lastName) {
        this.token = token;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    public AuthResponse(String email, boolean requiresVerification) {
        this.email = email;
        this.requiresVerification = requiresVerification;
    }
}
