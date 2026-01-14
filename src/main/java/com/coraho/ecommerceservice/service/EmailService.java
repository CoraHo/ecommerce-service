package com.coraho.ecommerceservice.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import com.coraho.ecommerceservice.exception.EmailVerificationException;

import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {
    private final JavaMailSender javaMailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Value("${app.name}")
    private String appName;

    public void sendVerificationEmail(String toEmail, String firstName, String verificationLink) {
        try {
            MimeMessage message = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail, appName);
            helper.setTo(toEmail);
            helper.setSubject("Verify Your Email Address");

            String htmlContent = buildVerificationEmailTemplate(firstName, verificationLink);
            helper.setText(htmlContent, true);

            javaMailSender.send(message);
            log.info("Verification email sent to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send verification email to: {}", toEmail, e.getMessage());
            throw new EmailVerificationException("Failed to send verification email: " + e.getMessage());
        }
    }

    private String buildVerificationEmailTemplate(String firstName, String verificationLink) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .button {
                            display: inline-block;
                            padding: 12px 24px;
                            background-color: #007bff;
                            color: #ffffff;
                            text-decoration: none;
                            border-radius: 4px;
                            margin: 20px 0;
                        }
                        .footer { margin-top: 30px; font-size: 12px; color: #666; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h2>Welcome to %s!</h2>
                        <p>Hi %s,</p>
                        <p>Thank you for registering. Please verify your email address by clicking the button below:</p>
                        <a href="%s" class="button">Verify Email Address</a>
                        <p>Or copy and paste this link into your browser:</p>
                        <p>%s</p>
                        <p>This link will expire in 24 hours.</p>
                        <div class="footer">
                            <p>If you didn't create this account, please ignore this email.</p>
                            <p>&copy; 2025 %s. All rights reserved.</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(appName, firstName, verificationLink, verificationLink, appName);
    }

}
