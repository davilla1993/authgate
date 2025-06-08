package com.follysitou.authgate.service;

import com.follysitou.authgate.exceptions.ValidationException;
import org.springframework.stereotype.Service;

@Service
public class PasswordValidatorService {


    public void validatePassword(String password) {

        if (password.length() < 8) {
            throw new ValidationException("Password must contain at least 8 characters");
        }

        if (!password.matches("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\\S+$).{10,}$")) {
            throw new ValidationException("The password must contain at least: \" +\n" +
                    "\" 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character");
        }
    }

}
