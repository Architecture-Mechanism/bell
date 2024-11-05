// Copyright (C) 2024 Bellande Architecture Mechanism Research Innovation Center, Ronaldson Bellande

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::time::Duration;

use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use chrono::{DateTime, Utc};
use log::error;
use serde::{Deserialize, Serialize};
use std::io::Write;
use thiserror::Error;
use totp_rs::Secret;

use crate::audit::audit::log_audit_event;
use crate::config::config::Config;
use crate::user_privilege::privilege::PrivilegeLevel;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub username: String,
    pub password_hash: String,
    pub privilege: PrivilegeLevel,
    pub totp_secret: String,
    pub groups: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub password_changed_at: DateTime<Utc>,
    pub failed_login_attempts: u32,
    pub locked_until: Option<DateTime<Utc>>,
    pub settings: UserSettings,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserSettings {
    pub require_mfa: bool,
    pub password_expiry_days: u32,
    pub max_failed_attempts: u32,
    pub lockout_duration: Duration,
    pub allowed_ip_ranges: Vec<String>,
}

#[derive(Error, Debug)]
pub enum UserError {
    #[error("User not found: {0}")]
    UserNotFound(String),
    #[error("User already exists: {0}")]
    UserExists(String),
    #[error("Invalid password: {0}")]
    InvalidPassword(String),
    #[error("Account locked: {0}")]
    AccountLocked(String),
    #[error("Password expired")]
    PasswordExpired,
    #[error("Invalid group: {0}")]
    InvalidGroup(String),
}

impl Default for UserSettings {
    fn default() -> Self {
        Self {
            require_mfa: true,
            password_expiry_days: 90,
            max_failed_attempts: 5,
            lockout_duration: Duration::from_secs(1800), // 30 minutes
            allowed_ip_ranges: vec!["127.0.0.1/8".to_string()],
        }
    }
}

impl User {
    pub fn new(username: &str, password: &str, privilege: PrivilegeLevel) -> Result<Self> {
        let password_hash = hash_password(password)?;
        let totp_secret = generate_totp_secret();
        let now = Utc::now();

        Ok(Self {
            username: username.to_string(),
            password_hash,
            privilege,
            totp_secret,
            groups: Vec::new(),
            created_at: now,
            last_login: None,
            password_changed_at: now,
            failed_login_attempts: 0,
            locked_until: None,
            settings: UserSettings::default(),
        })
    }

    pub fn is_locked(&self) -> bool {
        if let Some(locked_until) = self.locked_until {
            Utc::now() < locked_until
        } else {
            false
        }
    }

    pub fn password_expired(&self) -> bool {
        let expiry = chrono::Duration::days(self.settings.password_expiry_days as i64);
        Utc::now() - self.password_changed_at > expiry
    }

    pub fn record_login_attempt(&mut self, success: bool) {
        if success {
            self.last_login = Some(Utc::now());
            self.failed_login_attempts = 0;
            self.locked_until = None;
        } else {
            self.failed_login_attempts += 1;
            if self.failed_login_attempts >= self.settings.max_failed_attempts {
                self.locked_until = Some(
                    Utc::now()
                        + chrono::Duration::from_std(self.settings.lockout_duration).unwrap(),
                );
            }
        }
    }
}

pub async fn add_user(
    config: &mut Config,
    username: &str,
    password: &str,
    privilege: PrivilegeLevel,
) -> Result<()> {
    // Check if user already exists
    if config.users.iter().any(|u| u.username == username) {
        return Err(UserError::UserExists(username.to_string()).into());
    }

    // Create new user
    let new_user = User::new(username, password, privilege)?;

    // Create OS-specific user account
    create_os_user(username, privilege).await?;

    config.users.push(new_user.clone());
    config.save()?;

    log_audit_event(
        "USER_ADDED",
        "SYSTEM",
        &format!("Added user: {} with privilege: {:?}", username, privilege),
    )
    .await?;

    println!(
        "User added successfully. TOTP secret: {}",
        new_user.totp_secret
    );
    Ok(())
}

pub async fn remove_user(config: &mut Config, username: &str) -> Result<()> {
    // Check if user exists
    if !config.users.iter().any(|u| u.username == username) {
        return Err(UserError::UserNotFound(username.to_string()).into());
    }

    // Remove OS-specific user account
    remove_os_user(username).await?;

    config.users.retain(|u| u.username != username);
    config.save()?;

    log_audit_event(
        "USER_REMOVED",
        "SYSTEM",
        &format!("Removed user: {}", username),
    )
    .await?;

    println!("User removed successfully.");
    Ok(())
}

pub async fn change_password(
    config: &mut Config,
    username: &str,
    new_password: &str,
) -> Result<()> {
    // Validate password complexity first
    validate_password_complexity(new_password)?;

    // Find user index
    let user_index = config
        .users
        .iter()
        .position(|u| u.username == username)
        .ok_or_else(|| UserError::UserNotFound(username.to_string()))?;

    // Update password
    let new_hash = hash_password(new_password)?;

    // Update the user's password
    {
        let user = &mut config.users[user_index];
        user.password_hash = new_hash;
        user.password_changed_at = Utc::now();
    }

    // Update OS-specific password
    update_os_password(username, new_password).await?;

    config.save()?;

    log_audit_event(
        "PASSWORD_CHANGED",
        username,
        "Password changed successfully",
    )
    .await?;

    println!("Password changed successfully.");
    Ok(())
}

pub async fn change_privilege(
    config: &mut Config,
    username: &str,
    new_privilege: PrivilegeLevel,
) -> Result<()> {
    // Find user index first
    let user_index = config
        .users
        .iter()
        .position(|u| u.username == username)
        .ok_or_else(|| UserError::UserNotFound(username.to_string()))?;

    // Get the values we need before modifying the user
    let old_privilege = config.users[user_index].privilege;
    let username_clone = config.users[user_index].username.clone();

    // Update the privilege
    config.users[user_index].privilege = new_privilege;

    // Update OS-specific privileges
    update_os_privileges(username, new_privilege).await?;

    // Save the configuration
    config.save()?;

    // Log the audit event
    log_audit_event(
        "PRIVILEGE_CHANGED",
        &username_clone,
        &format!(
            "Privilege changed from {:?} to {:?}",
            old_privilege, new_privilege
        ),
    )
    .await?;

    println!("Privilege level changed successfully.");
    Ok(())
}

pub async fn add_user_to_group(
    config: &mut Config,
    username: &str,
    group_name: &str,
) -> Result<()> {
    // Check if group exists first
    if !config.groups.iter().any(|g| g.name == group_name) {
        return Err(UserError::InvalidGroup(group_name.to_string()).into());
    }

    // Find user index
    let user_index = config
        .users
        .iter()
        .position(|u| u.username == username)
        .ok_or_else(|| UserError::UserNotFound(username.to_string()))?;

    // Check if user is already in group
    let already_in_group = config.users[user_index]
        .groups
        .contains(&group_name.to_string());

    if !already_in_group {
        // Get username for audit log before modification
        let username_clone = config.users[user_index].username.clone();

        // Add user to group
        config.users[user_index].groups.push(group_name.to_string());

        // Update OS-specific group membership
        add_os_user_to_group(username, group_name).await?;

        // Save configuration
        config.save()?;

        // Log audit event
        log_audit_event(
            "USER_ADDED_TO_GROUP",
            &username_clone,
            &format!("Added to group: {}", group_name),
        )
        .await?;

        println!("User added to group successfully.");
    } else {
        println!("User is already in this group.");
    }

    Ok(())
}

pub async fn remove_user_from_group(
    config: &mut Config,
    username: &str,
    group_name: &str,
) -> Result<()> {
    // Find user index
    let user_index = config
        .users
        .iter()
        .position(|u| u.username == username)
        .ok_or_else(|| UserError::UserNotFound(username.to_string()))?;

    // Get username for audit log before modification
    let username_clone = config.users[user_index].username.clone();

    // Remove the group
    config.users[user_index].groups.retain(|g| g != group_name);

    // Update OS-specific group membership
    remove_os_user_from_group(username, group_name).await?;

    // Save configuration
    config.save()?;

    // Log audit event
    log_audit_event(
        "USER_REMOVED_FROM_GROUP",
        &username_clone,
        &format!("Removed from group: {}", group_name),
    )
    .await?;

    println!("User removed from group successfully.");
    Ok(())
}

// Helper functions
fn hash_password(password: &str) -> Result<String> {
    // Generate a random salt
    let salt = SaltString::generate(&mut OsRng);

    // Create default Argon2 instance
    let argon2 = Argon2::default();

    // Hash the password
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

// And here's a corresponding verify function you'll need
fn verify_password(hash: &str, password: &str) -> Result<bool> {
    use argon2::password_hash::PasswordHash;
    use argon2::PasswordVerifier;

    // Parse the hash string into a PasswordHash instance
    let parsed_hash = PasswordHash::new(hash)?;

    // Verify the password against the hash
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

fn generate_totp_secret() -> String {
    Secret::generate_secret().to_string()
}

fn validate_password_complexity(password: &str) -> Result<()> {
    if password.len() < 12 {
        return Err(UserError::InvalidPassword("Password too short".to_string()).into());
    }

    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_digit(10));
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    if !(has_uppercase && has_lowercase && has_digit && has_special) {
        return Err(UserError::InvalidPassword(
            "Password does not meet complexity requirements".to_string(),
        )
        .into());
    }

    Ok(())
}

// OS-specific functions
async fn create_os_user(username: &str, privilege: PrivilegeLevel) -> Result<()> {
    match std::env::consts::OS {
        "macos" => create_macos_user(username, privilege).await,
        "linux" => create_linux_user(username, privilege).await,
        "bellandeos" => create_bellande_user(username, privilege).await,
        _ => Ok(()),
    }
}

async fn remove_os_user(username: &str) -> Result<()> {
    match std::env::consts::OS {
        "macos" => remove_macos_user(username).await,
        "linux" => remove_linux_user(username).await,
        "bellandeos" => remove_bellande_user(username).await,
        _ => Ok(()),
    }
}

async fn update_os_password(username: &str, password: &str) -> Result<()> {
    match std::env::consts::OS {
        "macos" => update_macos_password(username, password).await,
        "linux" => update_linux_password(username, password).await,
        "bellandeos" => update_bellande_password(username, password).await,
        _ => Ok(()),
    }
}

async fn update_os_privileges(username: &str, privilege: PrivilegeLevel) -> Result<()> {
    match std::env::consts::OS {
        "macos" => update_macos_privileges(username, privilege).await,
        "linux" => update_linux_privileges(username, privilege).await,
        "bellandeos" => update_bellande_privileges(username, privilege).await,
        _ => Ok(()),
    }
}

// OS-specific implementations for macOS, Linux, and BellandeOS...
async fn create_macos_user(username: &str, privilege: PrivilegeLevel) -> Result<()> {
    let mut cmd = std::process::Command::new("sysadminctl");
    cmd.args(&["-addUser", username]);

    match privilege {
        PrivilegeLevel::Administrator => {
            cmd.arg("-admin");
        }
        _ => {}
    }

    cmd.output().context("Failed to create macOS user")?;
    Ok(())
}

async fn create_linux_user(username: &str, privilege: PrivilegeLevel) -> Result<()> {
    let mut cmd = std::process::Command::new("useradd");
    cmd.arg(username);

    match privilege {
        PrivilegeLevel::Administrator => {
            cmd.args(&["-G", "sudo"]);
        }
        _ => {}
    }

    cmd.output().context("Failed to create Linux user")?;
    Ok(())
}

async fn create_bellande_user(username: &str, privilege: PrivilegeLevel) -> Result<()> {
    let mut cmd = std::process::Command::new("bellctl");
    cmd.args(&["user", "create", username]);

    match privilege {
        PrivilegeLevel::Administrator => {
            cmd.arg("--admin");
        }
        PrivilegeLevel::Root => {
            cmd.arg("--root");
        }
        PrivilegeLevel::Bell => {
            cmd.arg("--bell");
        }
        _ => {}
    }

    cmd.output().context("Failed to create BellandeOS user")?;
    Ok(())
}

async fn remove_macos_user(username: &str) -> Result<()> {
    std::process::Command::new("sysadminctl")
        .args(&["-deleteUser", username])
        .output()
        .context("Failed to remove macOS user")?;
    Ok(())
}

async fn remove_linux_user(username: &str) -> Result<()> {
    std::process::Command::new("userdel")
        .args(&["-r", username]) // -r flag removes home directory and mail spool
        .output()
        .context("Failed to remove Linux user")?;
    Ok(())
}

async fn remove_bellande_user(username: &str) -> Result<()> {
    std::process::Command::new("bellctl")
        .args(&["user", "remove", username])
        .output()
        .context("Failed to remove BellandeOS user")?;
    Ok(())
}

async fn update_macos_password(username: &str, password: &str) -> Result<()> {
    std::process::Command::new("dscl")
        .args(&[".", "-passwd", &format!("/Users/{}", username), password])
        .output()
        .context("Failed to update macOS password")?;
    Ok(())
}

async fn update_linux_password(username: &str, password: &str) -> Result<()> {
    let passwd_input = format!("{}:{}", username, password);
    let mut child = std::process::Command::new("chpasswd")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("Failed to spawn chpasswd")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(passwd_input.as_bytes())
            .context("Failed to write to chpasswd stdin")?;
    }

    child.wait().context("Failed to wait for chpasswd")?;
    Ok(())
}

async fn update_bellande_password(username: &str, password: &str) -> Result<()> {
    let mut child = std::process::Command::new("bellctl")
        .args(&["user", "set-password", username])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("Failed to spawn bellctl")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(password.as_bytes())
            .context("Failed to set BellandeOS password")?;
    }

    child.wait().context("Failed to wait for bellctl")?;
    Ok(())
}

async fn update_macos_privileges(username: &str, privilege: PrivilegeLevel) -> Result<()> {
    match privilege {
        PrivilegeLevel::Administrator | PrivilegeLevel::Root | PrivilegeLevel::Bell => {
            std::process::Command::new("dseditgroup")
                .args(&["-o", "edit", "-a", username, "-t", "user", "admin"])
                .output()
                .context("Failed to update macOS privileges")?;
        }
        _ => {
            std::process::Command::new("dseditgroup")
                .args(&["-o", "edit", "-d", username, "-t", "user", "admin"])
                .output()
                .context("Failed to update macOS privileges")?;
        }
    }
    Ok(())
}

async fn update_linux_privileges(username: &str, privilege: PrivilegeLevel) -> Result<()> {
    match privilege {
        PrivilegeLevel::Administrator | PrivilegeLevel::Root => {
            std::process::Command::new("usermod")
                .args(&["-aG", "sudo", username])
                .output()
                .context("Failed to update Linux privileges")?;
        }
        PrivilegeLevel::Bell => {
            std::process::Command::new("usermod")
                .args(&["-aG", "sudo,adm,root", username])
                .output()
                .context("Failed to update Linux privileges")?;
        }
        _ => {
            std::process::Command::new("deluser")
                .args(&[username, "sudo"])
                .output()
                .context("Failed to update Linux privileges")?;
        }
    }
    Ok(())
}

async fn update_bellande_privileges(username: &str, privilege: PrivilegeLevel) -> Result<()> {
    let privilege_str = match privilege {
        PrivilegeLevel::User => "user",
        PrivilegeLevel::Group => "group",
        PrivilegeLevel::Administrator => "admin",
        PrivilegeLevel::Root => "root",
        PrivilegeLevel::Bell => "bell",
    };

    std::process::Command::new("bellctl")
        .args(&["user", "set-privilege", username, privilege_str])
        .output()
        .context("Failed to update BellandeOS privileges")?;
    Ok(())
}

async fn add_os_user_to_group(username: &str, group: &str) -> Result<()> {
    match std::env::consts::OS {
        "macos" => {
            std::process::Command::new("dseditgroup")
                .args(&["-o", "edit", "-a", username, "-t", "user", group])
                .output()
                .context("Failed to add macOS user to group")?;
        }
        "linux" => {
            std::process::Command::new("usermod")
                .args(&["-aG", group, username])
                .output()
                .context("Failed to add Linux user to group")?;
        }
        "bellandeos" => {
            std::process::Command::new("bellctl")
                .args(&["user", "add-to-group", username, group])
                .output()
                .context("Failed to add BellandeOS user to group")?;
        }
        _ => {}
    }
    Ok(())
}

async fn remove_os_user_from_group(username: &str, group: &str) -> Result<()> {
    match std::env::consts::OS {
        "macos" => {
            std::process::Command::new("dseditgroup")
                .args(&["-o", "edit", "-d", username, "-t", "user", group])
                .output()
                .context("Failed to remove macOS user from group")?;
        }
        "linux" => {
            std::process::Command::new("deluser")
                .args(&[username, group])
                .output()
                .context("Failed to remove Linux user from group")?;
        }
        "bellandeos" => {
            std::process::Command::new("bellctl")
                .args(&["user", "remove-from-group", username, group])
                .output()
                .context("Failed to remove BellandeOS user from group")?;
        }
        _ => {}
    }
    Ok(())
}
