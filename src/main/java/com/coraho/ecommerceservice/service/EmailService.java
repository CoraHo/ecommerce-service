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
            log.error("Failed to send verification email to: {}. {}", toEmail, e.getMessage());
            throw new EmailVerificationException("Failed to send verification email: " + e.getMessage());
        }
    }

    public void sendPasswordResetEmail(String toEmail, String firstName, String verificationLink) {
        try {
            MimeMessage message = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail, appName);
            helper.setTo(toEmail);
            helper.setSubject("Reset your password");

            String htmlContent = buildPasswordResetEmailTemplate(firstName, verificationLink);
            helper.setText(htmlContent, true);

            javaMailSender.send(message);
            log.info("Password reset email sent to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send password reset email to: {}. {}", toEmail, e.getMessage());
            throw new EmailVerificationException("Failed to send password reset email: " + e.getMessage());
        }
    }

    public void sendPasswordResetConfirmationEmail(String toEmail, String firstName) {
        try {
            MimeMessage message = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail, appName);
            helper.setTo(toEmail);
            helper.setSubject("Your password has been updated");

            String htmlContent = buildPasswordResetConfirmationEmail(firstName);
            helper.setText(htmlContent, true);

            javaMailSender.send(message);
            log.info("Password reset confirmation email sent to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send password reset confirmation email to: {}. {}", toEmail, e.getMessage());
            throw new EmailVerificationException("Failed to send password reset confirmation email: " + e.getMessage());
        }
    }

    public void sendNewIPLoggedInEmail(String toEmail, String firstName, String ipAddress) {
        try {
            MimeMessage message = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail, appName);
            helper.setTo(toEmail);
            helper.setSubject("New Login Detected");

            String htmlContent = buildNewIPLoggedInEmail(firstName, ipAddress);
            helper.setText(htmlContent, true);

            javaMailSender.send(message);
            log.info("New IP Login email sent to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send new IP login email to: {}. {}", toEmail, e.getMessage());
            throw new EmailVerificationException("Failed to send new IP login email: " + e.getMessage());
        }

    }

    private String buildPasswordResetEmailTemplate(String firstName, String verificationLink) {
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
                        <p>Please reset your password by clicking the button below:</p>
                        <a href="%s" class="button">Reset Password</a>
                        <p>Or copy and paste this link into your browser:</p>
                        <p>%s</p>
                        <p>This link will expire in 5 minutes.</p>
                        <div class="footer">
                            <p>If you didn't request this, please ignore this email.</p>
                            <p>&copy; 2025 %s. All rights reserved.</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(appName, firstName, verificationLink, verificationLink, appName);
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
                        <p>This link will expire in 5 minutes.</p>
                        <div class="footer">
                            <p>If you didn't request this, please ignore this email.</p>
                            <p>&copy; 2025 %s. All rights reserved.</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(appName, firstName, verificationLink, verificationLink, appName);
    }

    private String buildPasswordResetConfirmationEmail(String firstName) {
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
                        <p>You're password has been reset successfully!</p>

                        <div class="footer">
                            <p>If you didn't request this, please contact us immediately.</p>
                            <p>&copy; 2025 %s. All rights reserved.</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(appName, firstName, appName);
    }

    private String buildNewIPLoggedInEmail(String firstName, String ipAddress) {
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
                        <h2>New Login Detected</h2>
                        <p>Hi %s,</p>
                        <p>We noticed a login from a IP Address: %s we haven't seen before.</p>

                        <div class="footer">
                            <p>If you didn't do this, please contact us immediately.</p>
                            <p>&copy; 2025 %s. All rights reserved.</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(firstName, ipAddress, appName);
    }
}
