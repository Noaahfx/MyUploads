To Install:
pip install flask flask_mysqldb werkzeug requests pyotp qrcode twilio oauthlib pillow numpy pandas opencv-python tensorflow gdown mtcnn retina-face tf-keras

Admin:
Username: Admin
Password: Pa$$w0rd

Database Script:
-- Create the database if it doesn't exist
CREATE DATABASE IF NOT EXISTS `secprj` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;

-- Use the newly created database
USE `secprj`;

-- Create the users table if it doesn't exist
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) NOT NULL UNIQUE,
    `password` VARCHAR(255) NOT NULL,
    `email` VARCHAR(100) NOT NULL UNIQUE,
    `mfa_secret` VARCHAR(32) DEFAULT NULL,
    `mfa_enabled` BOOLEAN DEFAULT FALSE,
    `email_verified` BOOLEAN DEFAULT FALSE,
    `verification_token` VARCHAR(255) DEFAULT NULL,
    `mfa_method` ENUM('none', 'app', 'email', 'sms') DEFAULT 'none',
    `email_2fa_code` VARCHAR(6) DEFAULT NULL,
    `email_2fa_expiration` DATETIME DEFAULT NULL,
    `face_image` VARCHAR(100) DEFAULT NULL,
    `phone_number` VARCHAR(20) DEFAULT NULL,
    `phone_verified` BOOLEAN DEFAULT FALSE,
    `phone_verification_code` VARCHAR(6) DEFAULT NULL,
    `sms_2fa_code` VARCHAR(6) DEFAULT NULL,
    `sms_2fa_expiration` DATETIME DEFAULT NULL,
    `role` VARCHAR(50) NOT NULL DEFAULT 'user',
    `otp_code` VARCHAR(6) DEFAULT NULL,
    `otp_expiration` DATETIME DEFAULT NULL
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;

-- Create the files table if it doesn't exist
CREATE TABLE IF NOT EXISTS `files` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `filename` VARCHAR(255) NOT NULL,
    `filepath` VARCHAR(255) NOT NULL,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;

-- Create the devices table to track user devices
CREATE TABLE IF NOT EXISTS `devices` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `device_hash` VARCHAR(255) NOT NULL,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;

-- Create the users_groups table if it doesn't exist
CREATE TABLE IF NOT EXISTS `users_groups` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(255) NOT NULL UNIQUE,
    `created_by` INT NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `is_active` BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (`created_by`) REFERENCES `users`(`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;

-- Create the group_memberships table if it doesn't exist
CREATE TABLE IF NOT EXISTS `group_memberships` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `group_id` INT NOT NULL,
    `user_id` INT NOT NULL,
    `joined_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `role` ENUM('group_leader', 'group_user') DEFAULT 'group_user',
    FOREIGN KEY (`group_id`) REFERENCES `users_groups`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;

-- Create the group_files table if it doesn't exist
CREATE TABLE IF NOT EXISTS `group_files` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `group_id` INT NOT NULL,
    `filename` VARCHAR(255) NOT NULL,
    `filepath` VARCHAR(255) NOT NULL,
    `uploaded_by` INT NOT NULL,
    FOREIGN KEY (`group_id`) REFERENCES `users_groups`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`uploaded_by`) REFERENCES `users`(`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;

-- Create the group_invitations table if it doesn't exist
CREATE TABLE IF NOT EXISTS `group_invitations` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `group_id` INT NOT NULL,
    `inviter_id` INT NOT NULL,
    `invitee_username` VARCHAR(255) NOT NULL,
    `status` ENUM('pending', 'accepted', 'declined') DEFAULT 'pending',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`group_id`) REFERENCES `users_groups`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`inviter_id`) REFERENCES `users`(`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;

-- Create the user_session_logs table if it doesn't exist
CREATE TABLE IF NOT EXISTS `user_session_logs` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) NOT NULL,
    `session_id` VARCHAR(255) NOT NULL,
    `log_in_time` DATETIME NOT NULL,
    `log_out_time` DATETIME DEFAULT NULL,
    `duration` TIME DEFAULT NULL,
    `log_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;

-- Create the previous_passwords table if it doesn't exist
CREATE TABLE IF NOT EXISTS `previous_passwords` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `password_hash` VARCHAR(255) NOT NULL,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;

INSERT INTO users (username, email, password, role, email_verified, mfa_enabled, mfa_method, mfa_secret, phone_number, phone_verified, email_2fa_code, email_2fa_expiration)
VALUES ('admin', 'admin@example.com', 'scrypt:32768:8:1$cnxjLQWgYdvDkmb8$1bd9db2ebf587e0cf6bb99acb297a6cb3a20ec8caf2980af55b832f13c2ad619dfa84e184c10e996688a35afd753ad7c86144aa1ef81ef8e83bc26c401e06268', 'admin', TRUE, FALSE, NULL, NULL, NULL, FALSE, NULL, NULL);