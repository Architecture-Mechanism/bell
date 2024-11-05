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

use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use log::error;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::audit::audit::log_audit_event;
use crate::config::config::Config;
use crate::user_privilege::user::User;
use chrono::Timelike;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Clone, Copy)]
pub enum PrivilegeLevel {
    User,          // Basic user privileges
    Group,         // Group-based privileges
    Administrator, // Administrative privileges
    Root,          // Root-level access
    Bell,          // Highest level - system owner
}

#[derive(Error, Debug)]
pub enum PrivilegeLevelError {
    #[error("Invalid privilege level: {0}")]
    InvalidPrivilegeLevel(String),
    #[error("Insufficient privileges")]
    InsufficientPrivileges,
    #[error("Expired privileges")]
    ExpiredPrivileges,
    #[error("Group not found: {0}")]
    GroupNotFound(String),
    #[error("Permission not found: {0}")]
    PermissionNotFound(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PrivilegeConfig {
    pub elevation_timeout: Duration,
    pub require_mfa: bool,
    pub allowed_elevation_hours: Vec<u8>,
    pub max_concurrent_elevations: usize,
    pub restricted_commands: HashMap<PrivilegeLevel, Vec<String>>,
}

impl Default for PrivilegeConfig {
    fn default() -> Self {
        Self {
            elevation_timeout: Duration::from_secs(3600),
            require_mfa: true,
            allowed_elevation_hours: (0..24).collect(),
            max_concurrent_elevations: 3,
            restricted_commands: HashMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct PrivilegeManager {
    config: PrivilegeConfig,
    active_elevations: HashMap<String, Vec<PrivilegeElevation>>,
}

#[derive(Debug)]
struct PrivilegeElevation {
    level: PrivilegeLevel,
    granted_at: SystemTime,
    expires_at: SystemTime,
    reason: String,
}

impl FromStr for PrivilegeLevel {
    type Err = PrivilegeLevelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "user" => Ok(PrivilegeLevel::User),
            "group" => Ok(PrivilegeLevel::Group),
            "admin" | "administrator" => Ok(PrivilegeLevel::Administrator),
            "root" => Ok(PrivilegeLevel::Root),
            "bell" => Ok(PrivilegeLevel::Bell),
            _ => Err(PrivilegeLevelError::InvalidPrivilegeLevel(s.to_string())),
        }
    }
}

impl fmt::Display for PrivilegeLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivilegeLevel::User => write!(f, "user"),
            PrivilegeLevel::Group => write!(f, "group"),
            PrivilegeLevel::Administrator => write!(f, "administrator"),
            PrivilegeLevel::Root => write!(f, "root"),
            PrivilegeLevel::Bell => write!(f, "bell"),
        }
    }
}

impl PrivilegeManager {
    pub fn new(config: PrivilegeConfig) -> Self {
        Self {
            config,
            active_elevations: HashMap::new(),
        }
    }

    pub async fn check_permission(
        &self,
        user: &User,
        required_privilege: PrivilegeLevel,
        config: &Config,
    ) -> Result<bool> {
        // Direct privilege level check
        if user.privilege >= required_privilege {
            log_audit_event(
                "PRIVILEGE_CHECK",
                &user.username,
                &format!("Direct privilege granted: {:?}", required_privilege),
            )
            .await?;
            return Ok(true);
        }

        // Check active elevations
        if let Some(elevations) = self.active_elevations.get(&user.username) {
            for elevation in elevations {
                if elevation.level >= required_privilege && SystemTime::now() < elevation.expires_at
                {
                    log_audit_event(
                        "PRIVILEGE_CHECK",
                        &user.username,
                        &format!("Elevation privilege granted: {:?}", required_privilege),
                    )
                    .await?;
                    return Ok(true);
                }
            }
        }

        // Check group permissions
        for group_name in &user.groups {
            if let Some(group) = config.groups.iter().find(|g| g.name == *group_name) {
                if group.permissions.contains(&required_privilege.to_string()) {
                    log_audit_event(
                        "PRIVILEGE_CHECK",
                        &user.username,
                        &format!(
                            "Group privilege granted: {:?} from {}",
                            required_privilege, group_name
                        ),
                    )
                    .await?;
                    return Ok(true);
                }
            }
        }

        log_audit_event(
            "PRIVILEGE_CHECK",
            &user.username,
            &format!("Permission denied for: {:?}", required_privilege),
        )
        .await?;
        Ok(false)
    }

    pub async fn elevate_privilege(
        &mut self,
        user: &User,
        requested_level: PrivilegeLevel,
        reason: &str,
        mfa_token: Option<&str>,
    ) -> Result<()> {
        // Check if elevation is allowed at current hour
        let current_hour = chrono::Local::now().hour() as u8;
        if !self.config.allowed_elevation_hours.contains(&current_hour) {
            return Err(PrivilegeLevelError::InsufficientPrivileges.into());
        }

        // Check MFA requirement
        if self.config.require_mfa && mfa_token.is_none() {
            return Err(anyhow::anyhow!(
                "MFA token required for privilege elevation"
            ));
        }

        // Check concurrent elevations
        let user_elevations = self
            .active_elevations
            .entry(user.username.clone())
            .or_default();
        if user_elevations.len() >= self.config.max_concurrent_elevations {
            return Err(anyhow::anyhow!("Maximum concurrent elevations reached"));
        }

        // Create new elevation
        let elevation = PrivilegeElevation {
            level: requested_level,
            granted_at: SystemTime::now(),
            expires_at: SystemTime::now() + self.config.elevation_timeout,
            reason: reason.to_string(),
        };

        user_elevations.push(elevation);

        log_audit_event(
            "PRIVILEGE_ELEVATION",
            &user.username,
            &format!("Elevated to {:?} for reason: {}", requested_level, reason),
        )
        .await?;

        Ok(())
    }

    pub async fn revoke_elevation(&mut self, user: &str, level: PrivilegeLevel) -> Result<()> {
        if let Some(elevations) = self.active_elevations.get_mut(user) {
            elevations.retain(|e| e.level != level);
            log_audit_event(
                "PRIVILEGE_REVOCATION",
                user,
                &format!("Revoked elevation: {:?}", level),
            )
            .await?;
        }
        Ok(())
    }

    pub fn cleanup_expired_elevations(&mut self) {
        let now = SystemTime::now();
        for elevations in self.active_elevations.values_mut() {
            elevations.retain(|e| e.expires_at > now);
        }
    }
}

// OS-specific privilege checks
pub async fn check_os_specific_privileges(
    user: &User,
    required_privilege: PrivilegeLevel,
) -> Result<bool> {
    match std::env::consts::OS {
        "macos" => check_macos_privileges(user, required_privilege).await,
        "linux" => check_linux_privileges(user, required_privilege).await,
        "bellandeos" => check_bellande_privileges(user, required_privilege).await,
        _ => Ok(false),
    }
}

async fn check_macos_privileges(user: &User, required_privilege: PrivilegeLevel) -> Result<bool> {
    // Check admin group membership
    if required_privilege >= PrivilegeLevel::Administrator {
        let output = std::process::Command::new("dseditgroup")
            .args(&["-o", "checkmember", "-m", &user.username, "admin"])
            .output()?;

        if !output.status.success() {
            return Ok(false);
        }
    }

    Ok(true)
}

async fn check_linux_privileges(user: &User, required_privilege: PrivilegeLevel) -> Result<bool> {
    // Check sudo group membership
    if required_privilege >= PrivilegeLevel::Administrator {
        let output = std::process::Command::new("groups")
            .arg(&user.username)
            .output()?;

        let groups = String::from_utf8_lossy(&output.stdout);
        if !groups.contains("sudo") && !groups.contains("wheel") {
            return Ok(false);
        }
    }

    Ok(true)
}

async fn check_bellande_privileges(
    user: &User,
    required_privilege: PrivilegeLevel,
) -> Result<bool> {
    // Check BellandeOS specific privileges
    let output = std::process::Command::new("bellctl")
        .args(&[
            "user",
            "check-privilege",
            &user.username,
            &required_privilege.to_string(),
        ])
        .output()?;

    Ok(output.status.success())
}
