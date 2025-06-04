package com.follysitou.authgate.service;

import org.springframework.stereotype.Service;

@Service
public class PasswordValidatorService {


    public void validatePassword(String password) {

        if (password.length() < 10) {
            throw new IllegalArgumentException("Le mot de passe doit contenir au moins 10 caractères");
        }

        if (!password.matches("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\\S+$).{10,}$")) {
            throw new IllegalArgumentException("Le mot de passe doit contenir au moins : " +
                                                    "1 majuscule, 1 minuscule, 1 chiffre et 1 caractère spécial");
        }
    }

}
