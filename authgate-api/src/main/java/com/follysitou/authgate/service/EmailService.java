package com.follysitou.authgate.service;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {


    private final JavaMailSender mailSender;

    public void sendVerificationCode(String to, String code, String subject, String messagePrefix) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject(subject);
        message.setText(messagePrefix + code +
                "\n\nCe code expire dans 10 minutes." +
                "\n\nSi vous n'avez pas demandé ce code, ignorez ce message.");

        mailSender.send(message);
    }

    public void sendPasswordResetToken(String to, String token) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Réinitialisation de mot de passe");
        message.setText("Pour réinitialiser votre mot de passe, utilisez le token suivant : " + token +
                "\n\nCe token expire dans 1 heure." +
                "\n\nSi vous n'avez pas demandé cette réinitialisation, ignorez ce message.");

        mailSender.send(message);
    }
}

