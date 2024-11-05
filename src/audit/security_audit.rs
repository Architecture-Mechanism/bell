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

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use log::info;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use sysinfo::{ProcessExt, System, SystemExt};
use walkdir::WalkDir;

use crate::audit::audit::log_audit_event;
use crate::config::config::Config;

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityAuditConfig {
    pub critical_paths: Vec<PathBuf>,
    pub suspicious_process_patterns: Vec<String>,
    pub allowed_ports: HashSet<u16>,
    pub file_hash_database: PathBuf,
    pub scan_interval: Duration,
}

impl Default for SecurityAuditConfig {
    fn default() -> Self {
        SecurityAuditConfig {
            critical_paths: get_os_critical_paths(),
            suspicious_process_patterns: vec![
                "crypto".to_string(),
                "miner".to_string(),
                "suspicious".to_string(),
            ],
            allowed_ports: [80, 443, 22, 53].iter().cloned().collect(),
            file_hash_database: PathBuf::from("file_hashes.db"),
            scan_interval: Duration::from_secs(3600),
        }
    }
}

fn get_os_critical_paths() -> Vec<PathBuf> {
    match std::env::consts::OS {
        "macos" => vec![
            PathBuf::from("/etc"),
            PathBuf::from("/System"),
            PathBuf::from("/usr/local/bin"),
        ],
        "linux" => vec![
            PathBuf::from("/etc"),
            PathBuf::from("/bin"),
            PathBuf::from("/sbin"),
        ],
        "bellandeos" => vec![
            PathBuf::from("/bell/etc"),
            PathBuf::from("/bell/bin"),
            PathBuf::from("/bell/security"),
        ],
        _ => vec![],
    }
}

/// Performs a comprehensive security audit of the system
pub async fn perform_security_audit(config: &Config) -> Result<()> {
    let audit_config = SecurityAuditConfig::default();
    info!("Starting security audit for {}", std::env::consts::OS);

    // Check for system updates
    check_system_updates().await?;

    // Scan for vulnerabilities
    scan_for_vulnerabilities(&audit_config).await?;

    // Check for suspicious processes
    check_suspicious_processes(&audit_config).await?;

    // Check for unauthorized users
    check_unauthorized_users(config).await?;

    // Check for open ports
    check_open_ports(&audit_config).await?;

    // Check file integrity
    check_file_integrity(&audit_config).await?;

    // OS-specific security checks
    perform_os_specific_checks().await?;

    log_audit_event(
        "SECURITY_AUDIT",
        "SYSTEM",
        &format!("Completed security audit on {}", std::env::consts::OS),
    )
    .await?;

    Ok(())
}

async fn check_system_updates() -> Result<()> {
    match std::env::consts::OS {
        "macos" => {
            let output = Command::new("softwareupdate")
                .arg("--list")
                .output()
                .context("Failed to check for macOS updates")?;

            if !output.stdout.is_empty() {
                log_audit_event("SECURITY_AUDIT", "SYSTEM", "macOS updates available").await?;
            }
        }
        "linux" => {
            let output = Command::new("apt")
                .args(&["list", "--upgradable"])
                .output()
                .context("Failed to check for Linux updates")?;

            if !output.stdout.is_empty() {
                log_audit_event("SECURITY_AUDIT", "SYSTEM", "Linux updates available").await?;
            }
        }
        "bellandeos" => {
            let output = Command::new("bellctl")
                .args(&["update", "check"])
                .output()
                .context("Failed to check for BellandeOS updates")?;

            if !output.stdout.is_empty() {
                log_audit_event("SECURITY_AUDIT", "SYSTEM", "BellandeOS updates available").await?;
            }
        }
        _ => anyhow::bail!("Unsupported operating system"),
    }

    Ok(())
}

async fn scan_for_vulnerabilities(config: &SecurityAuditConfig) -> Result<()> {
    log_audit_event("SECURITY_AUDIT", "SYSTEM", "Starting vulnerability scan").await?;

    // Check for known vulnerable software versions
    check_software_versions().await?;

    // Check for common misconfigurations
    check_common_misconfigurations(config).await?;

    // Check for weak permissions
    check_permissions(config).await?;

    log_audit_event("SECURITY_AUDIT", "SYSTEM", "Vulnerability scan completed").await?;
    Ok(())
}

async fn check_software_versions() -> Result<()> {
    // Check OpenSSL version
    let openssl_version = Command::new("openssl")
        .arg("version")
        .output()
        .context("Failed to check OpenSSL version")?;

    if !openssl_version.status.success() {
        log_audit_event(
            "SECURITY_AUDIT",
            "SYSTEM",
            "Warning: Unable to verify OpenSSL version",
        )
        .await?;
    }

    Ok(())
}

async fn check_common_misconfigurations(config: &SecurityAuditConfig) -> Result<()> {
    for path in &config.critical_paths {
        check_path_permissions(path).await?;
    }

    // Check world-writable files
    check_world_writable_files().await?;

    // Check for dangerous SUID/SGID binaries
    check_suid_binaries().await?;

    Ok(())
}

async fn check_permissions(config: &SecurityAuditConfig) -> Result<()> {
    for path in &config.critical_paths {
        let metadata = fs::metadata(path).context("Failed to get path metadata")?;
        let mode = metadata.permissions().mode();

        if mode & 0o777 > 0o755 {
            log_audit_event(
                "SECURITY_AUDIT",
                "SYSTEM",
                &format!("Excessive permissions found on: {:?}", path),
            )
            .await?;
        }
    }
    Ok(())
}

async fn check_path_permissions(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path).context("Failed to get path metadata")?;
    let mode = metadata.permissions().mode();

    // Check for excessive permissions
    if mode & 0o777 > 0o755 {
        log_audit_event(
            "SECURITY_AUDIT",
            "SYSTEM",
            &format!(
                "Warning: Excessive permissions ({:o}) on path: {:?}",
                mode & 0o777,
                path
            ),
        )
        .await?;
    }

    // Check owner/group
    if mode & 0o7000 != 0 {
        log_audit_event(
            "SECURITY_AUDIT",
            "SYSTEM",
            &format!(
                "Warning: Special bits ({:o}) set on path: {:?}",
                mode & 0o7000,
                path
            ),
        )
        .await?;
    }

    Ok(())
}

async fn check_world_writable_files() -> Result<()> {
    let critical_directories = match std::env::consts::OS {
        "macos" => vec!["/etc", "/usr", "/bin", "/sbin", "/System"],
        "linux" => vec!["/etc", "/usr", "/bin", "/sbin", "/lib", "/boot"],
        "bellandeos" => vec!["/bell/etc", "/bell/bin", "/bell/lib", "/bell/security"],
        _ => vec![],
    };

    for dir in critical_directories {
        for entry in WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if let Ok(metadata) = fs::metadata(path) {
                let mode = metadata.permissions().mode();

                // Check for world-writable permissions (others write permission)
                if mode & 0o002 != 0 {
                    log_audit_event(
                        "SECURITY_AUDIT",
                        "SYSTEM",
                        &format!("Warning: World-writable file found: {:?}", path),
                    )
                    .await?;
                }
            }
        }
    }

    Ok(())
}

async fn check_suid_binaries() -> Result<()> {
    let critical_directories = match std::env::consts::OS {
        "macos" => vec!["/usr/bin", "/usr/sbin", "/usr/local/bin"],
        "linux" => vec!["/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"],
        "bellandeos" => vec!["/bell/bin", "/bell/sbin", "/bell/local/bin"],
        _ => vec![],
    };

    // Known safe SUID binaries
    let safe_suid_binaries = HashSet::from([
        "ping",
        "su",
        "sudo",
        "passwd",
        "mount",
        "umount",
        "fusermount",
        "newgrp",
        "chsh",
        "gpasswd",
    ]);

    for dir in critical_directories {
        for entry in WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if let Ok(metadata) = fs::metadata(path) {
                let mode = metadata.permissions().mode();

                // Check for SUID/SGID bits
                if mode & 0o6000 != 0 {
                    // Get binary name
                    let binary_name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown");

                    // If it's not in our safe list, log it
                    if !safe_suid_binaries.contains(binary_name) {
                        log_audit_event(
                            "SECURITY_AUDIT",
                            "SYSTEM",
                            &format!(
                                "Warning: SUID/SGID binary found: {:?} (mode: {:o})",
                                path,
                                mode & 0o7777
                            ),
                        )
                        .await?;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn check_suspicious_processes(config: &SecurityAuditConfig) -> Result<()> {
    let system = System::new_all();

    for (pid, process) in system.processes() {
        let process_name = process.name().to_lowercase();

        for pattern in &config.suspicious_process_patterns {
            if process_name.contains(pattern) {
                log_audit_event(
                    "SECURITY_AUDIT",
                    "SYSTEM",
                    &format!("Suspicious process found: {} (PID: {})", process_name, pid),
                )
                .await?;

                // Additional process information
                if let Some(cmd) = process.cmd().first() {
                    log_audit_event(
                        "SECURITY_AUDIT",
                        "SYSTEM",
                        &format!("Process command: {}", cmd),
                    )
                    .await?;
                }
            }
        }
    }

    Ok(())
}

async fn check_unauthorized_users(config: &Config) -> Result<()> {
    match std::env::consts::OS {
        "macos" => check_macos_users(config).await?,
        "linux" => check_linux_users(config).await?,
        "bellandeos" => check_bellande_users(config).await?,
        _ => anyhow::bail!("Unsupported operating system"),
    }

    Ok(())
}

async fn check_macos_users(config: &Config) -> Result<()> {
    let output = Command::new("dscl")
        .args(&[".", "list", "/Users"])
        .output()
        .context("Failed to list macOS users")?;

    let users = String::from_utf8_lossy(&output.stdout);
    for user in users.lines() {
        if !config.users.iter().any(|u| u.username == user) && !is_macos_system_user(user) {
            log_audit_event(
                "SECURITY_AUDIT",
                "SYSTEM",
                &format!("Unauthorized macOS user found: {}", user),
            )
            .await?;
        }
    }

    Ok(())
}

async fn check_linux_users(config: &Config) -> Result<()> {
    let passwd = fs::read_to_string("/etc/passwd").context("Failed to read /etc/passwd")?;

    for line in passwd.lines() {
        let username = line.split(':').next().unwrap_or("");
        if !config.users.iter().any(|u| u.username == username) && !is_linux_system_user(username) {
            log_audit_event(
                "SECURITY_AUDIT",
                "SYSTEM",
                &format!("Unauthorized Linux user found: {}", username),
            )
            .await?;
        }
    }

    Ok(())
}

async fn check_bellande_users(config: &Config) -> Result<()> {
    let output = Command::new("bellctl")
        .args(&["user", "list"])
        .output()
        .context("Failed to list BellandeOS users")?;

    let users = String::from_utf8_lossy(&output.stdout);
    for user in users.lines() {
        if !config.users.iter().any(|u| u.username == user) && !is_bellande_system_user(user) {
            log_audit_event(
                "SECURITY_AUDIT",
                "SYSTEM",
                &format!("Unauthorized BellandeOS user found: {}", user),
            )
            .await?;
        }
    }

    Ok(())
}

fn is_macos_system_user(username: &str) -> bool {
    matches!(
        username,
        "_spotlight" | "_locationd" | "_mdnsresponder" | "root" | "daemon"
    )
}

fn is_linux_system_user(username: &str) -> bool {
    matches!(
        username,
        "root"
            | "daemon"
            | "bin"
            | "sys"
            | "sync"
            | "games"
            | "man"
            | "lp"
            | "mail"
            | "news"
            | "uucp"
            | "proxy"
            | "www-data"
            | "backup"
            | "list"
            | "irc"
            | "gnats"
            | "nobody"
            | "systemd-network"
            | "systemd-resolve"
            | "systemd-timesync"
            | "messagebus"
            | "syslog"
            | "avahi"
            | "_apt"
            | "sshd"
    )
}

fn is_bellande_system_user(username: &str) -> bool {
    matches!(
        username,
        "bellroot" | "bellsys" | "bellservice" | "bellnetwork" | "bellsecurity"
    )
}

async fn check_open_ports(config: &SecurityAuditConfig) -> Result<()> {
    match std::env::consts::OS {
        "macos" => {
            let output = Command::new("lsof")
                .args(&["-i", "-P", "-n"])
                .output()
                .context("Failed to check macOS open ports")?;

            check_port_output(
                &String::from_utf8_lossy(&output.stdout),
                &config.allowed_ports,
            )
            .await?;
        }
        "linux" => {
            let output = Command::new("netstat")
                .args(&["-tuln"])
                .output()
                .context("Failed to check Linux open ports")?;

            check_port_output(
                &String::from_utf8_lossy(&output.stdout),
                &config.allowed_ports,
            )
            .await?;
        }
        "bellandeos" => {
            let output = Command::new("bellctl")
                .args(&["network", "ports"])
                .output()
                .context("Failed to check BellandeOS open ports")?;

            check_port_output(
                &String::from_utf8_lossy(&output.stdout),
                &config.allowed_ports,
            )
            .await?;
        }
        _ => anyhow::bail!("Unsupported operating system"),
    }

    Ok(())
}

async fn check_port_output(output: &str, allowed_ports: &HashSet<u16>) -> Result<()> {
    for line in output.lines() {
        if line.contains("LISTEN") {
            let port = extract_port_from_line(line);
            if let Some(port) = port {
                if !allowed_ports.contains(&port) {
                    log_audit_event(
                        "SECURITY_AUDIT",
                        "SYSTEM",
                        &format!("Unauthorized open port found: {}", port),
                    )
                    .await?;
                }
            }
        }
    }
    Ok(())
}

fn extract_port_from_line(line: &str) -> Option<u16> {
    line.split(':')
        .last()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

async fn check_file_integrity(config: &SecurityAuditConfig) -> Result<()> {
    // Initialize or load hash database
    let mut hash_database = load_hash_database(&config.file_hash_database)?;

    for path in &config.critical_paths {
        check_directory_integrity(path, &mut hash_database).await?;
    }

    // Save updated hashes
    save_hash_database(&config.file_hash_database, &hash_database)?;

    Ok(())
}

async fn check_directory_integrity(
    path: &Path,
    hash_database: &mut HashMap<PathBuf, String>,
) -> Result<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                let current_hash = calculate_file_hash(&path)?;

                if let Some(stored_hash) = hash_database.get(&path) {
                    if stored_hash != &current_hash {
                        log_audit_event(
                            "SECURITY_AUDIT",
                            "SYSTEM",
                            &format!("File integrity mismatch: {:?}", path),
                        )
                        .await?;
                    }
                }
                // Update hash in database
                hash_database.insert(path, current_hash);
            } else if path.is_dir() {
                Box::pin(check_directory_integrity(&path, hash_database)).await?;
            }
        }
    }
    Ok(())
}

async fn perform_os_specific_checks() -> Result<()> {
    match std::env::consts::OS {
        "macos" => perform_macos_specific_checks().await?,
        "linux" => perform_linux_specific_checks().await?,
        "bellandeos" => perform_bellande_specific_checks().await?,
        _ => anyhow::bail!("Unsupported operating system"),
    }
    Ok(())
}

async fn perform_macos_specific_checks() -> Result<()> {
    // Check System Integrity Protection (SIP)
    let sip_status = Command::new("csrutil")
        .arg("status")
        .output()
        .context("Failed to check SIP status")?;

    if !String::from_utf8_lossy(&sip_status.stdout).contains("enabled") {
        log_audit_event(
            "SECURITY_AUDIT",
            "SYSTEM",
            "Warning: System Integrity Protection is disabled",
        )
        .await?;
    }

    // Check FileVault status
    let filevault_status = Command::new("fdesetup")
        .arg("status")
        .output()
        .context("Failed to check FileVault status")?;

    if !String::from_utf8_lossy(&filevault_status.stdout).contains("On") {
        log_audit_event(
            "SECURITY_AUDIT",
            "SYSTEM",
            "Warning: FileVault is not enabled",
        )
        .await?;
    }

    // Check Gatekeeper status
    let gatekeeper_status = Command::new("spctl")
        .args(&["--status"])
        .output()
        .context("Failed to check Gatekeeper status")?;

    if !String::from_utf8_lossy(&gatekeeper_status.stdout).contains("enabled") {
        log_audit_event(
            "SECURITY_AUDIT",
            "SYSTEM",
            "Warning: Gatekeeper is disabled",
        )
        .await?;
    }

    Ok(())
}

async fn perform_linux_specific_checks() -> Result<()> {
    // Check SELinux status
    if Path::new("/etc/selinux/config").exists() {
        let selinux_status = Command::new("getenforce")
            .output()
            .context("Failed to check SELinux status")?;

        if !String::from_utf8_lossy(&selinux_status.stdout).contains("Enforcing") {
            log_audit_event(
                "SECURITY_AUDIT",
                "SYSTEM",
                "Warning: SELinux is not in enforcing mode",
            )
            .await?;
        }
    }

    // Check AppArmor status
    if Path::new("/etc/apparmor").exists() {
        let apparmor_status = Command::new("aa-status")
            .output()
            .context("Failed to check AppArmor status")?;

        if !apparmor_status.status.success() {
            log_audit_event(
                "SECURITY_AUDIT",
                "SYSTEM",
                "Warning: AppArmor is not properly configured",
            )
            .await?;
        }
    }

    // Check kernel parameters
    check_kernel_parameters().await?;

    Ok(())
}

async fn perform_bellande_specific_checks() -> Result<()> {
    // Check BellandeOS security module status
    let security_status = Command::new("bellctl")
        .args(&["security", "status"])
        .output()
        .context("Failed to check BellandeOS security status")?;

    if !String::from_utf8_lossy(&security_status.stdout).contains("enabled") {
        log_audit_event(
            "SECURITY_AUDIT",
            "SYSTEM",
            "Warning: BellandeOS security module is not enabled",
        )
        .await?;
    }

    // Check BellandeOS integrity
    let integrity_check = Command::new("bellctl")
        .args(&["verify", "system"])
        .output()
        .context("Failed to verify BellandeOS integrity")?;

    if !integrity_check.status.success() {
        log_audit_event(
            "SECURITY_AUDIT",
            "SYSTEM",
            "Warning: BellandeOS system integrity check failed",
        )
        .await?;
    }

    // Check BellandeOS update status
    let update_status = Command::new("bellctl")
        .args(&["update", "status"])
        .output()
        .context("Failed to check BellandeOS update status")?;

    if !update_status.status.success() {
        log_audit_event(
            "SECURITY_AUDIT",
            "SYSTEM",
            "Warning: BellandeOS update check failed",
        )
        .await?;
    }

    Ok(())
}

async fn check_kernel_parameters() -> Result<()> {
    let critical_params = [
        "kernel.randomize_va_space",
        "kernel.kptr_restrict",
        "kernel.dmesg_restrict",
        "kernel.perf_event_paranoid",
        "net.ipv4.tcp_syncookies",
    ];

    for param in &critical_params {
        let output = Command::new("sysctl")
            .arg(param)
            .output()
            .context(format!("Failed to check kernel parameter: {}", param))?;

        if !output.status.success() {
            log_audit_event(
                "SECURITY_AUDIT",
                "SYSTEM",
                &format!("Warning: Failed to verify kernel parameter: {}", param),
            )
            .await?;
        }
    }

    Ok(())
}

fn calculate_file_hash(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn load_hash_database(path: &Path) -> Result<HashMap<PathBuf, String>> {
    if path.exists() {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(serde_json::from_reader(reader)?)
    } else {
        Ok(HashMap::new())
    }
}

fn save_hash_database(path: &Path, database: &HashMap<PathBuf, String>) -> Result<()> {
    let file = File::create(path)?;
    serde_json::to_writer_pretty(file, database)?;
    Ok(())
}
