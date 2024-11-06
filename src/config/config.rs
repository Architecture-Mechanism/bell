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

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use log::warn;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;

use crate::hsm::hsm::{decrypt_data, encrypt_data};
use crate::user_privilege::user::User;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub users: Vec<User>,
    pub groups: Vec<Group>,
    pub session_duration: u64,
    pub allowed_commands: Vec<String>,
    pub denied_commands: Vec<String>,
    pub allowed_networks: Vec<String>,
    pub hsm_slot: u64,
    pub hsm_pin: String,
    pub security_settings: SecuritySettings,
    pub os_specific: OsSpecificConfig,
    pub paths: ConfigPaths,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    pub permissions: Vec<String>,
    pub members: Vec<String>,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub modified_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecuritySettings {
    pub password_min_length: usize,
    pub password_require_special: bool,
    pub password_require_numbers: bool,
    pub password_require_uppercase: bool,
    pub max_login_attempts: usize,
    pub lockout_duration: Duration,
    pub session_timeout: Duration,
    pub mfa_required: bool,
    pub allowed_ip_ranges: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsSpecificConfig {
    pub macos: MacOSConfig,
    pub linux: LinuxConfig,
    pub bellandeos: BellandeOSConfig,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MacOSConfig {
    pub require_filevault: bool,
    pub require_sip: bool,
    pub allowed_applications: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct LinuxConfig {
    pub selinux_mode: String,
    pub require_apparmor: bool,
    pub kernel_hardening: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BellandeOSConfig {
    pub security_level: String,
    pub require_secure_boot: bool,
    pub enable_kernel_protection: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigPaths {
    pub config_dir: PathBuf,
    pub log_dir: PathBuf,
    pub backup_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        let os_paths = match std::env::consts::OS {
            "macos" => ConfigPaths {
                config_dir: PathBuf::from("/Library/Application Support/bell"),
                log_dir: PathBuf::from("/var/log/bell"),
                backup_dir: PathBuf::from("/var/backup/bell"),
            },
            "linux" => ConfigPaths {
                config_dir: PathBuf::from("/etc/bell"),
                log_dir: PathBuf::from("/var/log/bell"),
                backup_dir: PathBuf::from("/var/backup/bell"),
            },
            "bellandeos" => ConfigPaths {
                config_dir: PathBuf::from("/bell/etc/bell"),
                log_dir: PathBuf::from("/bell/log/bell"),
                backup_dir: PathBuf::from("/bell/backup/bell"),
            },
            _ => ConfigPaths {
                config_dir: PathBuf::from("./config"),
                log_dir: PathBuf::from("./log"),
                backup_dir: PathBuf::from("./backup"),
            },
        };

        Config {
            users: Vec::new(),
            groups: Vec::new(),
            session_duration: 3600,
            allowed_commands: get_default_allowed_commands(),
            denied_commands: get_default_denied_commands(),
            allowed_networks: vec!["127.0.0.1/8".to_string()],
            hsm_slot: 0,
            hsm_pin: String::new(),
            security_settings: SecuritySettings {
                password_min_length: 12,
                password_require_special: true,
                password_require_numbers: true,
                password_require_uppercase: true,
                max_login_attempts: 3,
                lockout_duration: Duration::from_secs(300),
                session_timeout: Duration::from_secs(3600),
                mfa_required: true,
                allowed_ip_ranges: vec!["192.168.0.0/16".to_string()],
            },
            os_specific: OsSpecificConfig {
                macos: MacOSConfig {
                    require_filevault: true,
                    require_sip: true,
                    allowed_applications: vec![],
                },
                linux: LinuxConfig {
                    selinux_mode: "enforcing".to_string(),
                    require_apparmor: true,
                    kernel_hardening: true,
                },
                bellandeos: BellandeOSConfig {
                    security_level: "high".to_string(),
                    require_secure_boot: true,
                    enable_kernel_protection: true,
                },
            },
            paths: os_paths,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let rt = Runtime::new()?;
        rt.block_on(async {
            let config_path = Self::get_config_path()?;
            Self::ensure_directories_exist()?;

            let encrypted_config =
                fs::read_to_string(&config_path).context("Failed to read config file")?;

            let decrypted_config = decrypt_data(&encrypted_config)
                .await
                .context("Failed to decrypt config file")?;

            let mut config: Config =
                toml::from_str(&decrypted_config).context("Failed to parse config file")?;

            config.verify_integrity()?;
            config.update_os_settings()?;

            Ok(config)
        })
    }

    pub fn save(&self) -> Result<()> {
        let rt = Runtime::new()?;
        rt.block_on(async {
            self.verify_integrity()?;
            self.create_backup().await?;

            let config_str = toml::to_string(self).context("Failed to serialize config")?;
            let encrypted_config = encrypt_data(&config_str)
                .await
                .context("Failed to encrypt config")?;

            let config_path = Self::get_config_path()?;
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .mode(0o600)
                .open(&config_path)
                .context("Failed to open config file for writing")?;

            file.write_all(encrypted_config.as_bytes())
                .context("Failed to write config file")?;

            Ok(())
        })
    }

    fn get_config_path() -> Result<PathBuf> {
        let config = Config::default();
        let config_file = config.paths.config_dir.join("config.toml");
        Ok(config_file)
    }

    fn ensure_directories_exist() -> Result<()> {
        let config = Config::default();
        fs::create_dir_all(&config.paths.config_dir)?;
        fs::create_dir_all(&config.paths.log_dir)?;
        fs::create_dir_all(&config.paths.backup_dir)?;
        Ok(())
    }

    fn verify_integrity(&self) -> Result<()> {
        if self.users.is_empty() {
            warn!("No users defined in configuration");
        }

        for group in &self.groups {
            for permission in &group.permissions {
                if !is_valid_permission(permission) {
                    return Err(anyhow::anyhow!("Invalid permission: {}", permission));
                }
            }
        }

        let mut seen_users = HashSet::new();
        for user in &self.users {
            if !seen_users.insert(&user.username) {
                return Err(anyhow::anyhow!("Duplicate user: {}", user.username));
            }
        }

        Ok(())
    }

    async fn create_backup(&self) -> Result<()> {
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let backup_path = self
            .paths
            .backup_dir
            .join(format!("config_backup_{}.toml", timestamp));

        let config_str = toml::to_string(self)?;
        let encrypted_backup = encrypt_data(&config_str).await?;
        fs::write(backup_path, encrypted_backup)?;

        Ok(())
    }

    fn update_os_settings(&mut self) -> Result<()> {
        match std::env::consts::OS {
            "macos" => {
                self.os_specific.macos = MacOSConfig {
                    require_filevault: true,
                    require_sip: true,
                    allowed_applications: get_default_macos_applications(),
                };
            }
            "linux" => {
                self.os_specific.linux = LinuxConfig {
                    selinux_mode: "enforcing".to_string(),
                    require_apparmor: true,
                    kernel_hardening: true,
                };
            }
            "bellandeos" => {
                self.os_specific.bellandeos = BellandeOSConfig {
                    security_level: "high".to_string(),
                    require_secure_boot: true,
                    enable_kernel_protection: true,
                };
            }
            _ => warn!("Unsupported operating system"),
        }
        Ok(())
    }
}

fn get_default_allowed_commands() -> Vec<String> {
    match std::env::consts::OS {
        "macos" => vec!["ls".to_string(), "cd".to_string(), "pwd".to_string()],
        "linux" => vec!["ls".to_string(), "cd".to_string(), "pwd".to_string()],
        "bellandeos" => vec!["bellctl".to_string(), "ls".to_string(), "cd".to_string()],
        _ => vec![],
    }
}

fn get_default_denied_commands() -> Vec<String> {
    match std::env::consts::OS {
        "macos" => vec!["rm -rf /*".to_string(), "sudo su -".to_string()],
        "linux" => vec!["rm -rf /*".to_string(), "dd".to_string()],
        "bellandeos" => vec![
            "bellctl system reset".to_string(),
            "bellctl security disable".to_string(),
        ],
        _ => vec![],
    }
}

fn get_default_macos_applications() -> Vec<String> {
    vec![
        "/Applications/Terminal.app".to_string(),
        "/Applications/Utilities/Terminal.app".to_string(),
    ]
}

fn is_valid_permission(permission: &str) -> bool {
    matches!(
        permission,
        "read" | "write" | "execute" | "admin" | "system"
    )
}
