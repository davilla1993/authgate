package com.follysitou.authgate.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class EmailService {


    private final JavaMailSender mailSender;

    private final SpringTemplateEngine templateEngine;

    public void sendVerificationCode(String to, String code, String firstName) {
        Context context = new Context();
        context.setVariable("code", code);
        context.setVariable("firstName", firstName);

        String content = templateEngine.process("email/verification-code", context);

        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, "UTF-8");
        try {
            helper.setTo(to);
            helper.setSubject("Code de vérification");
            helper.setText(content, true);
            mailSender.send(message);
        } catch (MessagingException e) {
            throw new RuntimeException("Erreur lors de l'envoi de l'email", e);
        }
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

    public void sendAccountLockedEmail(String to, String reason,
                                       LocalDateTime lockTime,
                                       LocalDateTime unlockTime,
                                       String firstName) {

        Context context = new Context();
        context.setVariable("reason", reason);
        context.setVariable("lockTime", lockTime);
        context.setVariable("unlockTime", unlockTime);
        context.setVariable("firstName", firstName);

        String content = templateEngine.process("email/account-locked", context);

        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, "UTF-8");
        try {
            helper.setTo(to);
            helper.setSubject("Votre compte a été verrouillé");
            helper.setText(content, true);
            mailSender.send(message);
        } catch (MessagingException e) {
            throw new RuntimeException("Erreur lors de l'envoi de l'email", e);
        }
    }

    public void sendAccountUnlockedEmail(String to, String message) {
        SimpleMailMessage email = new SimpleMailMessage();
        email.setTo(to);
        email.setSubject("Votre compte a été déverrouillé");
        email.setText("Cher utilisateur,\n\n" + message +
                "\n\nCordialement,\nL'équipe de support");
        mailSender.send(email);
    }

    public void sendAccountManuallyLockedEmail(String to, String subject, String reason) {
        SimpleMailMessage email = new SimpleMailMessage();
        email.setTo(to);
        email.setSubject(subject);
        email.setText("Cher utilisateur,\n\n" +
                "Votre compte a été verrouillé manuellement pour la raison suivante :\n" +
                reason + "\n\n" +
                "Pour toute question, veuillez contacter l'administrateur.\n\n" +
                "Cordialement,\nL'équipe technique");
        mailSender.send(email);
    }

    public void sendPasswordExpirationWarning(String to, String subject, String message) {
        SimpleMailMessage email = new SimpleMailMessage();
        email.setTo(to);
        email.setSubject(subject);
        email.setText("Cher utilisateur,\n\n" + message +
                "\n\nVeuillez changer votre mot de passe dès que possible." +
                "\n\nCordialement,\nL'équipe de sécurité");
        mailSender.send(email);
    }
}

