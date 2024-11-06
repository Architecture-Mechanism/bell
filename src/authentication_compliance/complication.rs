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

use chrono::Utc;
use regex::Regex;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::unix::fs::MetadataExt;

use crate::audit::audit::log_audit_event;
use crate::config::config::Config;

#[derive(Debug)]
pub struct NetworkRequirements {
    pub required_protocols: Vec<String>,
    pub minimum_networks: usize,
    pub required_firewall: bool,
    pub required_encryption: bool,
}

#[derive(Debug)]
pub struct ComplianceConfig {
    // Original fields
    pub min_password_length: usize,
    pub min_password_entropy: f64,
    pub password_complexity_regex: String,
    pub critical_files: Vec<PathBuf>,
    pub required_services: Vec<String>,
    pub required_kernel_params: Vec<String>,
    pub audit_file_hashes: PathBuf,
    pub network_requirements: NetworkRequirements,

    // New password policy fields
    pub password_max_days: u32,
    pub password_min_days: u32,
    pub password_warn_days: u32,
    pub max_repeated_chars: usize,
}

#[derive(Debug)]
struct PasswordViolation {
    description: String,
    severity: ViolationSeverity,
}

#[derive(Debug)]
enum ViolationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        let security_paths = get_security_paths();
        let critical_files = security_paths.get("critical").cloned().unwrap_or_default();
        let services = get_security_services();
        let required_services = services.get("required").cloned().unwrap_or_default();

        ComplianceConfig {
            min_password_length: 12,
            min_password_entropy: 50.0,
            max_repeated_chars: 3,
            password_max_days: 90,
            password_min_days: 1,
            password_warn_days: 7,
            password_complexity_regex: String::from(
                r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$",
            ),
            critical_files,
            required_services,
            // Fix the type mismatch by converting HashMap to Vec<String>
            required_kernel_params: get_required_kernel_params()
                .into_iter()
                .map(|(key, value)| format!("{}={}", key, value))
                .collect(),
            audit_file_hashes: PathBuf::from("audit_hashes.db"),
            network_requirements: NetworkRequirements {
                required_protocols: vec![
                    "TLSv1.3".to_string(),
                    "SSHv2".to_string(),
                    "TLS_AES_256_GCM_SHA384".to_string(),
                    "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                ],
                minimum_networks: 1,
                required_firewall: true,
                required_encryption: true,
            },
        }
    }
}

fn get_security_paths() -> HashMap<String, Vec<PathBuf>> {
    let mut paths = HashMap::new();
    match std::env::consts::OS {
        "linux" => {
            paths.insert(
                "critical".to_string(),
                vec![
                    PathBuf::from("/etc/security/limits.conf"),
                    PathBuf::from("/etc/security/pwquality.conf"),
                    PathBuf::from("/etc/passwd"),
                    PathBuf::from("/etc/shadow"),
                    PathBuf::from("/etc/group"),
                    PathBuf::from("/etc/sudoers"),
                    PathBuf::from("/etc/ssh/sshd_config"),
                ],
            );
        }
        "bellandeos" => {
            paths.insert(
                "critical".to_string(),
                vec![
                    PathBuf::from("/bell/security/audit.conf"),
                    PathBuf::from("/bell/security/password.conf"),
                    PathBuf::from("/bell/security/users"),
                    PathBuf::from("/bell/security/access"),
                    PathBuf::from("/bell/security/keys"),
                    PathBuf::from("/bell/config/system"),
                ],
            );
        }
        "macos" => {
            paths.insert(
                "critical".to_string(),
                vec![
                    PathBuf::from("/etc/security/audit_control"),
                    PathBuf::from("/etc/security/pwpolicy"),
                    PathBuf::from("/etc/pam.d"),
                    PathBuf::from("/Library/Security"),
                    PathBuf::from("/etc/ssh/sshd_config"),
                ],
            );
        }
        _ => {}
    }
    paths
}

fn get_required_services() -> Vec<String> {
    match std::env::consts::OS {
        "macos" => vec![
            "com.apple.auditd".to_string(),
            "com.apple.security".to_string(),
        ],
        "linux" => vec!["auditd".to_string(), "sshd".to_string(), "ufw".to_string()],
        "bellandeos" => vec![
            "bell.audit".to_string(),
            "bell.security".to_string(),
            "bell.firewall".to_string(),
        ],
        _ => vec![],
    }
}

fn get_required_kernel_params() -> HashMap<String, String> {
    let mut params = HashMap::new();
    match std::env::consts::OS {
        "linux" => {
            // Memory protection
            params.insert("kernel.randomize_va_space".to_string(), "2".to_string());
            params.insert("kernel.kptr_restrict".to_string(), "1".to_string());
            params.insert("kernel.yama.ptrace_scope".to_string(), "1".to_string());
            params.insert("vm.mmap_min_addr".to_string(), "65536".to_string());

            // Network security
            params.insert("net.ipv4.tcp_syncookies".to_string(), "1".to_string());
            params.insert("net.ipv4.conf.all.rp_filter".to_string(), "1".to_string());
            params.insert(
                "net.ipv4.conf.default.rp_filter".to_string(),
                "1".to_string(),
            );
            params.insert(
                "net.ipv4.conf.all.accept_redirects".to_string(),
                "0".to_string(),
            );
            params.insert(
                "net.ipv6.conf.all.accept_redirects".to_string(),
                "0".to_string(),
            );
            params.insert(
                "net.ipv4.conf.all.send_redirects".to_string(),
                "0".to_string(),
            );
            params.insert(
                "net.ipv4.conf.all.accept_source_route".to_string(),
                "0".to_string(),
            );
            params.insert(
                "net.ipv6.conf.all.accept_source_route".to_string(),
                "0".to_string(),
            );

            // Core dumps
            params.insert("kernel.core_pattern".to_string(), "|/bin/false".to_string());
            params.insert("fs.suid_dumpable".to_string(), "0".to_string());

            // System security
            params.insert("kernel.sysrq".to_string(), "0".to_string());
            params.insert("kernel.dmesg_restrict".to_string(), "1".to_string());
            params.insert(
                "kernel.unprivileged_bpf_disabled".to_string(),
                "1".to_string(),
            );

            // Module loading
            params.insert("kernel.modules_disabled".to_string(), "1".to_string());

            // IPv6 security
            params.insert(
                "net.ipv6.conf.all.disable_ipv6".to_string(),
                "1".to_string(),
            );
            params.insert(
                "net.ipv6.conf.default.disable_ipv6".to_string(),
                "1".to_string(),
            );
        }
        "bellandeos" => {
            // General security
            params.insert("bell.security.level".to_string(), "high".to_string());
            params.insert("bell.memory.protection".to_string(), "strict".to_string());
            params.insert("bell.process.isolation".to_string(), "enforced".to_string());

            // System hardening
            params.insert("bell.kernel.hardening".to_string(), "maximum".to_string());
            params.insert("bell.syscall.filtering".to_string(), "strict".to_string());
            params.insert(
                "bell.exploit.prevention".to_string(),
                "aggressive".to_string(),
            );

            // Memory security
            params.insert("bell.memory.aslr".to_string(), "full".to_string());
            params.insert("bell.stack.protection".to_string(), "strong".to_string());
            params.insert("bell.heap.protection".to_string(), "strict".to_string());

            // Network security
            params.insert("bell.network.filtering".to_string(), "strict".to_string());
            params.insert("bell.network.isolation".to_string(), "enforced".to_string());
            params.insert(
                "bell.network.encryption".to_string(),
                "required".to_string(),
            );

            // Access control
            params.insert("bell.access.control".to_string(), "mandatory".to_string());
            params.insert(
                "bell.privilege.escalation".to_string(),
                "restricted".to_string(),
            );
            params.insert("bell.capability.control".to_string(), "strict".to_string());

            // Monitoring and auditing
            params.insert("bell.audit.level".to_string(), "comprehensive".to_string());
            params.insert("bell.monitoring.mode".to_string(), "active".to_string());
            params.insert("bell.incident.detection".to_string(), "enabled".to_string());
        }
        "macos" => {
            // While macOS doesn't use sysctl for all security settings,
            params.insert("kern.sugid_coredump".to_string(), "0".to_string());
            params.insert(
                "kern.bootargs".to_string(),
                "cs_enforcement_disable=0".to_string(),
            );
            params.insert("kern.secure_kernel".to_string(), "1".to_string());
            params.insert("net.inet.tcp.blackhole".to_string(), "2".to_string());
            params.insert("net.inet.udp.blackhole".to_string(), "1".to_string());
            params.insert("net.inet.icmp.icmplim".to_string(), "50".to_string());
            params.insert("net.inet.ip.forwarding".to_string(), "0".to_string());
            params.insert("net.inet.ip.redirect".to_string(), "0".to_string());
            params.insert("net.inet.tcp.always_keepalive".to_string(), "0".to_string());
            params.insert("net.inet.tcp.drop_synfin".to_string(), "1".to_string());
        }
        _ => {}
    }
    params
}

fn get_security_services() -> HashMap<String, Vec<String>> {
    let mut services = HashMap::new();
    match std::env::consts::OS {
        "linux" => {
            services.insert(
                "required".to_string(),
                vec![
                    "auditd".to_string(),
                    "fail2ban".to_string(),
                    "ufw".to_string(),
                    "apparmor".to_string(),
                    "systemd-journald".to_string(),
                ],
            );
            services.insert(
                "prohibited".to_string(),
                vec![
                    "telnet".to_string(),
                    "rsh".to_string(),
                    "rlogin".to_string(),
                    "rexec".to_string(),
                ],
            );
        }
        "bellandeos" => {
            services.insert(
                "required".to_string(),
                vec![
                    "bell.audit".to_string(),
                    "bell.security".to_string(),
                    "bell.firewall".to_string(),
                    "bell.intrusion_detection".to_string(),
                    "bell.integrity_monitor".to_string(),
                    "bell.endpoint_protection".to_string(),
                ],
            );
            services.insert(
                "prohibited".to_string(),
                vec![
                    "bell.legacy_protocols".to_string(),
                    "bell.unsecured_services".to_string(),
                ],
            );
        }
        "macos" => {
            services.insert(
                "required".to_string(),
                vec![
                    "com.apple.auditd".to_string(),
                    "com.apple.security.firewall".to_string(),
                    "com.apple.security.fdesetup".to_string(),
                    "com.apple.security.SecureIO".to_string(),
                ],
            );
            services.insert(
                "prohibited".to_string(),
                vec!["com.apple.tftp".to_string(), "com.apple.ftp".to_string()],
            );
        }
        _ => {}
    }
    services
}

pub async fn check_compliance(config: &Config) -> Result<()> {
    let compliance_config = ComplianceConfig::default();
    info!("Starting compliance check for {}", std::env::consts::OS);

    // Password compliance
    check_password_complexity(config, &compliance_config).await?;

    // File permissions
    check_file_permissions(&compliance_config).await?;

    // System configurations
    check_system_configurations(&compliance_config).await?;

    // Audit log integrity
    check_audit_log_integrity(&compliance_config).await?;

    // Network configurations
    check_network_configurations(config, &compliance_config).await?;

    // OS-specific checks
    perform_os_specific_checks(&compliance_config).await?;

    log_audit_event(
        "COMPLIANCE_CHECK",
        "SYSTEM",
        &format!("Completed compliance check on {}", std::env::consts::OS),
    )
    .await?;

    Ok(())
}

async fn check_password_complexity(
    config: &Config,
    compliance_config: &ComplianceConfig,
) -> Result<()> {
    let regex = Regex::new(&compliance_config.password_complexity_regex)
        .context("Failed to compile password complexity regex")?;

    for user in &config.users {
        let mut violations: Vec<PasswordViolation> = Vec::new();

        // Check hash length (Argon2)
        if user.password_hash.len() < 60 {
            violations.push(PasswordViolation {
                description: "Password hash does not meet length requirements".to_string(),
                severity: ViolationSeverity::High,
            });
        }

        // Check password expiry
        let days_since_change = (Utc::now() - user.password_changed_at).num_days();
        if days_since_change > compliance_config.password_max_days as i64 {
            violations.push(PasswordViolation {
                description: format!(
                    "Password expired {} days ago (max: {} days)",
                    days_since_change, compliance_config.password_max_days
                ),
                severity: ViolationSeverity::Medium,
            });
        }

        // Check if password will expire soon
        let days_until_expiry = compliance_config.password_max_days as i64 - days_since_change;
        if days_until_expiry <= compliance_config.password_warn_days as i64 && days_until_expiry > 0
        {
            violations.push(PasswordViolation {
                description: format!("Password will expire in {} days", days_until_expiry),
                severity: ViolationSeverity::Low,
            });
        }

        // Check additional password requirements
        if let Some(raw_password) = get_last_password_change(&user.username).await? {
            if !regex.is_match(&raw_password) {
                violations.push(PasswordViolation {
                    description: "Password does not meet complexity requirements".to_string(),
                    severity: ViolationSeverity::Critical,
                });
            }

            // Check minimum length
            if raw_password.len() < compliance_config.min_password_length {
                violations.push(PasswordViolation {
                    description: format!(
                        "Password length ({}) below minimum required ({})",
                        raw_password.len(),
                        compliance_config.min_password_length
                    ),
                    severity: ViolationSeverity::High,
                });
            }

            // Add detailed password validation
            let strength_violations = validate_password_strength(&raw_password, compliance_config);
            violations.extend(strength_violations);

            // Check for common passwords
            if is_common_password(&raw_password).await? {
                violations.push(PasswordViolation {
                    description: "Password found in common password list".to_string(),
                    severity: ViolationSeverity::Critical,
                });
            }

            // Check password entropy
            let entropy = calculate_password_entropy(&raw_password);
            if entropy < compliance_config.min_password_entropy {
                violations.push(PasswordViolation {
                    description: format!(
                        "Password entropy too low: {:.2} bits (minimum: {} bits)",
                        entropy, compliance_config.min_password_entropy
                    ),
                    severity: ViolationSeverity::High,
                });
            }
        }

        // Log all violations
        for violation in violations {
            log_audit_event(
                "COMPLIANCE_VIOLATION",
                &user.username,
                &format!(
                    "{} (Severity: {:?})",
                    violation.description, violation.severity
                ),
            )
            .await?;
        }
    }

    Ok(())
}
async fn is_common_password(password: &str) -> Result<bool> {
    // This could be implemented by checking against a BellandeSQL of common passwords
    // For now, we'll just check some basic patterns
    let common_patterns = [
        "password", "123456", "qwerty", "admin", "letmein", "welcome",
    ];

    Ok(common_patterns
        .iter()
        .any(|&pattern| password.contains(pattern)))
}

fn validate_password_strength(password: &str, config: &ComplianceConfig) -> Vec<PasswordViolation> {
    let mut violations: Vec<PasswordViolation> = Vec::new();

    // Check length
    if password.len() < config.min_password_length {
        violations.push(PasswordViolation {
            description: format!(
                "Password too short: {} chars (minimum {})",
                password.len(),
                config.min_password_length
            ),
            severity: ViolationSeverity::High,
        });
    }

    // Check for uppercase letters
    if !password.chars().any(|c| c.is_uppercase()) {
        violations.push(PasswordViolation {
            description: "Password must contain at least one uppercase letter".to_string(),
            severity: ViolationSeverity::Medium,
        });
    }

    // Check for lowercase letters
    if !password.chars().any(|c| c.is_lowercase()) {
        violations.push(PasswordViolation {
            description: "Password must contain at least one lowercase letter".to_string(),
            severity: ViolationSeverity::Medium,
        });
    }

    // Check for numbers
    if !password.chars().any(|c| c.is_numeric()) {
        violations.push(PasswordViolation {
            description: "Password must contain at least one number".to_string(),
            severity: ViolationSeverity::Medium,
        });
    }

    // Check for special characters
    if !password.chars().any(|c| !c.is_alphanumeric()) {
        violations.push(PasswordViolation {
            description: "Password must contain at least one special character".to_string(),
            severity: ViolationSeverity::Medium,
        });
    }

    // Check for repeating characters
    if has_repeating_chars(password, 3) {
        violations.push(PasswordViolation {
            description: "Password contains repeating characters".to_string(),
            severity: ViolationSeverity::Low,
        });
    }

    violations
}

// Helper function to check for repeating characters
fn has_repeating_chars(password: &str, max_repeats: usize) -> bool {
    let chars: Vec<char> = password.chars().collect();
    let mut repeat_count = 1;

    for i in 1..chars.len() {
        if chars[i] == chars[i - 1] {
            repeat_count += 1;
            if repeat_count > max_repeats {
                return true;
            }
        } else {
            repeat_count = 1;
        }
    }

    false
}

// Entropy calculation for password strength
fn calculate_password_entropy(password: &str) -> f64 {
    let mut charset_size = 0;

    // Check what types of characters are used
    let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
    let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
    let has_numbers = password.chars().any(|c| c.is_ascii_digit());
    let has_symbols = password.chars().any(|c| !c.is_alphanumeric());

    // Calculate charset size
    if has_lowercase {
        charset_size += 26;
    }
    if has_uppercase {
        charset_size += 26;
    }
    if has_numbers {
        charset_size += 10;
    }
    if has_symbols {
        charset_size += 32;
    }

    // Calculate entropy
    (password.len() as f64) * (charset_size as f64).log2()
}

#[cfg(target_family = "unix")]
async fn check_file_permissions(compliance_config: &ComplianceConfig) -> Result<()> {
    for file_path in &compliance_config.critical_files {
        let metadata = fs::metadata(file_path)
            .context(format!("Failed to get metadata for {:?}", file_path))?;

        // Use direct metadata mode() for Unix systems
        let mode = metadata.mode() & 0o777;

        // Check for secure permissions
        if mode != 0o600 {
            log_audit_event(
                "COMPLIANCE_VIOLATION",
                "SYSTEM",
                &format!("Incorrect permissions on {:?}: {:o}", file_path, mode),
            )
            .await?;
        }

        // Check ownership
        let uid = metadata.uid();
        if uid != 0 {
            log_audit_event(
                "COMPLIANCE_VIOLATION",
                "SYSTEM",
                &format!("Incorrect ownership on {:?}", file_path),
            )
            .await?;
        }

        // Check group ownership
        let gid = metadata.gid();
        if gid != 0 {
            log_audit_event(
                "COMPLIANCE_VIOLATION",
                "SYSTEM",
                &format!("Incorrect group ownership on {:?}: GID {}", file_path, gid),
            )
            .await?;
        }
    }
    Ok(())
}

#[cfg(target_family = "unix")]
async fn check_single_file_permissions(file_path: &Path) -> Result<()> {
    let metadata =
        fs::metadata(file_path).context(format!("Failed to get metadata for {:?}", file_path))?;

    let mode = metadata.mode() & 0o777;
    let uid = metadata.uid();
    let gid = metadata.gid();

    let mut violations = Vec::new();

    // Check basic permissions
    if mode != 0o600 {
        violations.push(format!("incorrect permissions: {:o}", mode));
    }

    // Check ownership
    if uid != 0 {
        violations.push(format!("incorrect owner UID: {}", uid));
    }

    // Check group
    if gid != 0 {
        violations.push(format!("incorrect group GID: {}", gid));
    }

    // Special bits check
    if mode & 0o7000 != 0 {
        violations.push(format!("special bits set: {:o}", mode & 0o7000));
    }

    // Log all violations if any found
    if !violations.is_empty() {
        log_audit_event(
            "COMPLIANCE_VIOLATION",
            "SYSTEM",
            &format!(
                "Security violations for {:?}: {}",
                file_path,
                violations.join(", ")
            ),
        )
        .await?;
    }

    Ok(())
}

async fn check_system_configurations(compliance_config: &ComplianceConfig) -> Result<()> {
    match std::env::consts::OS {
        "macos" => check_macos_configurations().await?,
        "linux" => check_linux_configurations(compliance_config).await?,
        "bellandeos" => check_bellande_configurations().await?,
        _ => warn!("System configuration checking not implemented for this OS"),
    }

    // Check required services
    for service in &compliance_config.required_services {
        if !is_service_running(service).await? {
            log_audit_event(
                "COMPLIANCE_VIOLATION",
                "SYSTEM",
                &format!("Required service not running: {}", service),
            )
            .await?;
        }
    }

    // Check kernel parameters
    for param in &compliance_config.required_kernel_params {
        let expected_value = get_expected_value(param)?;
        check_kernel_parameter(param, &expected_value).await?;
    }

    Ok(())
}

async fn check_kernel_parameter(param: &str, expected_value: &str) -> Result<()> {
    match std::env::consts::OS {
        "linux" => {
            let output = Command::new("sysctl")
                .arg(param)
                .output()
                .context(format!("Failed to check kernel parameter: {}", param))?;
            let value = String::from_utf8_lossy(&output.stdout);
            if !value.contains(expected_value) {
                log_audit_event(
                    "COMPLIANCE_VIOLATION",
                    "SYSTEM",
                    &format!("Kernel parameter {} has incorrect value", param),
                )
                .await?;
            }
        }
        "bellandeos" => {
            let output = Command::new("bellctl")
                .args(&["kernel", "param", param])
                .output()
                .context(format!("Failed to check BellandeOS parameter: {}", param))?;
            let value = String::from_utf8_lossy(&output.stdout);
            if !value.contains(expected_value) {
                log_audit_event(
                    "COMPLIANCE_VIOLATION",
                    "SYSTEM",
                    &format!("BellandeOS parameter {} has incorrect value", param),
                )
                .await?;
            }
        }
        _ => warn!("Kernel parameter checking not implemented for this OS"),
    }
    Ok(())
}

fn get_expected_value(param: &str) -> Result<String> {
    match param {
        "kernel.randomize_va_space" => Ok("2".to_string()),
        "net.ipv4.ip_forward" => Ok("0".to_string()),
        "kernel.yama.ptrace_scope" => Ok("1".to_string()),
        "kernel.kptr_restrict" => Ok("2".to_string()),
        "net.ipv4.conf.all.accept_redirects" => Ok("0".to_string()),
        "net.ipv4.conf.all.send_redirects" => Ok("0".to_string()),
        _ => Ok("0".to_string()),
    }
}

async fn get_kernel_parameter(param: &str) -> Result<String> {
    match std::env::consts::OS {
        "linux" => {
            let path = format!("/proc/sys/{}", param.replace(".", "/"));
            Ok(fs::read_to_string(path)?.trim().to_string())
        }
        _ => Ok("0".to_string()),
    }
}

async fn check_audit_log_integrity(compliance_config: &ComplianceConfig) -> Result<()> {
    // Load stored hashes
    let stored_hashes = load_file_hashes(&compliance_config.audit_file_hashes)?;

    // Check audit log file
    let audit_log_path = Path::new("audit_log.txt");
    if !audit_log_path.exists() {
        log_audit_event(
            "COMPLIANCE_VIOLATION",
            "SYSTEM",
            "Audit log file is missing",
        )
        .await?;
        return Ok(());
    }

    // Calculate current hash
    let current_hash = calculate_file_hash(audit_log_path)?;

    // Compare with stored hash
    if let Some(stored_hash) = stored_hashes.get(audit_log_path) {
        if current_hash != *stored_hash {
            log_audit_event(
                "COMPLIANCE_VIOLATION",
                "SYSTEM",
                "Audit log integrity check failed",
            )
            .await?;
        }
    } else {
        // Store initial hash
        save_file_hash(
            &compliance_config.audit_file_hashes,
            audit_log_path,
            &current_hash,
        )?;
    }

    Ok(())
}

async fn check_network_configurations(
    config: &Config,
    compliance_config: &ComplianceConfig,
) -> Result<()> {
    // Check network restrictions
    if config.allowed_networks.len() < compliance_config.network_requirements.minimum_networks {
        log_audit_event(
            "COMPLIANCE_VIOLATION",
            "SYSTEM",
            "Insufficient network restrictions configured",
        )
        .await?;
    }

    // Check firewall
    if compliance_config.network_requirements.required_firewall {
        check_firewall_status().await?;
    }

    // Check encryption requirements
    if compliance_config.network_requirements.required_encryption {
        check_network_encryption(&compliance_config.network_requirements).await?;
    }

    Ok(())
}

async fn perform_os_specific_checks(compliance_config: &ComplianceConfig) -> Result<()> {
    match std::env::consts::OS {
        "macos" => {
            // Check SIP status
            let sip_output = Command::new("csrutil")
                .arg("status")
                .output()
                .context("Failed to check SIP status")?;

            if !String::from_utf8_lossy(&sip_output.stdout).contains("enabled") {
                log_audit_event(
                    "COMPLIANCE_VIOLATION",
                    "SYSTEM",
                    "System Integrity Protection is disabled",
                )
                .await?;
            }

            // Check FileVault
            let filevault_output = Command::new("fdesetup")
                .arg("status")
                .output()
                .context("Failed to check FileVault status")?;

            if !String::from_utf8_lossy(&filevault_output.stdout).contains("On") {
                log_audit_event("COMPLIANCE_VIOLATION", "SYSTEM", "FileVault is not enabled")
                    .await?;
            }
        }
        "linux" => {
            // Check SELinux
            if !Path::new("/sys/fs/selinux/enforce").exists() {
                log_audit_event("COMPLIANCE_VIOLATION", "SYSTEM", "SELinux is not enabled").await?;
            }

            // Check AppArmor
            let apparmor_output = Command::new("aa-status")
                .output()
                .context("Failed to check AppArmor status")?;

            if !apparmor_output.status.success() {
                log_audit_event(
                    "COMPLIANCE_VIOLATION",
                    "SYSTEM",
                    "AppArmor is not properly configured",
                )
                .await?;
            }
        }
        "bellandeos" => {
            // Check BellandeOS security module
            let security_output = Command::new("bellctl")
                .args(&["security", "status"])
                .output()
                .context("Failed to check BellandeOS security status")?;

            if !String::from_utf8_lossy(&security_output.stdout).contains("enabled") {
                log_audit_event(
                    "COMPLIANCE_VIOLATION",
                    "SYSTEM",
                    "BellandeOS security module is not enabled",
                )
                .await?;
            }

            // Check BellandeOS integrity
            let integrity_output = Command::new("bellctl")
                .args(&["verify", "system"])
                .output()
                .context("Failed to verify BellandeOS integrity")?;

            if !integrity_output.status.success() {
                log_audit_event(
                    "COMPLIANCE_VIOLATION",
                    "SYSTEM",
                    "BellandeOS system integrity check failed",
                )
                .await?;
            }
        }
        _ => warn!("OS-specific checks not implemented for this operating system"),
    }

    Ok(())
}

async fn check_macos_configurations() -> Result<()> {
    // Check System Integrity Protection (SIP)
    let sip_output = Command::new("csrutil")
        .arg("status")
        .output()
        .context("Failed to check SIP status")?;

    if !String::from_utf8_lossy(&sip_output.stdout).contains("enabled") {
        log_audit_event(
            "COMPLIANCE_VIOLATION",
            "SYSTEM",
            "System Integrity Protection (SIP) is disabled",
        )
        .await?;
    }

    // Check FileVault encryption
    let filevault_output = Command::new("fdesetup")
        .arg("status")
        .output()
        .context("Failed to check FileVault status")?;

    if !String::from_utf8_lossy(&filevault_output.stdout).contains("FileVault is On") {
        log_audit_event(
            "COMPLIANCE_VIOLATION",
            "SYSTEM",
            "FileVault encryption is not enabled",
        )
        .await?;
    }

    // Check Gatekeeper status
    let gatekeeper_output = Command::new("spctl")
        .args(&["--status"])
        .output()
        .context("Failed to check Gatekeeper status")?;

    if !String::from_utf8_lossy(&gatekeeper_output.stdout).contains("assessments enabled") {
        log_audit_event(
            "COMPLIANCE_VIOLATION",
            "SYSTEM",
            "Gatekeeper is not enabled",
        )
        .await?;
    }

    // Check software update settings
    let update_output = Command::new("softwareupdate")
        .args(&["--schedule"])
        .output()
        .context("Failed to check software update schedule")?;

    if !String::from_utf8_lossy(&update_output.stdout).contains("enabled") {
        log_audit_event(
            "COMPLIANCE_VIOLATION",
            "SYSTEM",
            "Automatic software updates are not enabled",
        )
        .await?;
    }

    // Check firewall status
    let firewall_output = Command::new("defaults")
        .args(&["read", "/Library/Preferences/com.apple.alf", "globalstate"])
        .output()
        .context("Failed to check firewall status")?;

    if !String::from_utf8_lossy(&firewall_output.stdout)
        .trim()
        .eq("1")
    {
        log_audit_event("COMPLIANCE_VIOLATION", "SYSTEM", "Firewall is not enabled").await?;
    }

    Ok(())
}

async fn check_linux_configurations(compliance_config: &ComplianceConfig) -> Result<()> {
    // Check SELinux status
    if Path::new("/etc/selinux/config").exists() {
        let selinux_output = Command::new("getenforce")
            .output()
            .context("Failed to check SELinux status")?;

        if !String::from_utf8_lossy(&selinux_output.stdout).contains("Enforcing") {
            log_audit_event(
                "COMPLIANCE_VIOLATION",
                "SYSTEM",
                "SELinux is not in enforcing mode",
            )
            .await?;
        }
    }

    // Check firewall status (UFW)
    let ufw_output = Command::new("ufw")
        .arg("status")
        .output()
        .context("Failed to check UFW status")?;

    if !String::from_utf8_lossy(&ufw_output.stdout).contains("active") {
        log_audit_event(
            "COMPLIANCE_VIOLATION",
            "SYSTEM",
            "UFW firewall is not active",
        )
        .await?;
    }

    // Check system security settings
    check_sysctl_settings().await?;

    // Check important security files
    let security_files = ["/etc/shadow", "/etc/passwd", "/etc/group", "/etc/sudoers"];

    for file in &security_files {
        let metadata =
            fs::metadata(file).context(format!("Failed to check permissions for {}", file))?;

        let mode = metadata.permissions().mode();
        if mode & 0o777 != 0o600 {
            log_audit_event(
                "COMPLIANCE_VIOLATION",
                "SYSTEM",
                &format!("Incorrect permissions on {}: {:o}", file, mode & 0o777),
            )
            .await?;
        }
    }

    // Check for password policies
    check_password_policies().await?;

    // Check for core dumps
    check_core_dumps().await?;

    Ok(())
}

async fn check_bellande_configurations() -> Result<()> {
    // Check BellandeOS security module status
    let security_status = Command::new("bellctl")
        .args(&["security", "status"])
        .output()
        .context("Failed to check BellandeOS security status")?;

    if !String::from_utf8_lossy(&security_status.stdout).contains("enabled") {
        log_audit_event(
            "COMPLIANCE_VIOLATION",
            "SYSTEM",
            "BellandeOS security module is not enabled",
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
            "COMPLIANCE_VIOLATION",
            "SYSTEM",
            "BellandeOS system integrity check failed",
        )
        .await?;
    }

    // Check BellandeOS encryption status
    let encryption_status = Command::new("bellctl")
        .args(&["encryption", "status"])
        .output()
        .context("Failed to check encryption status")?;

    if !String::from_utf8_lossy(&encryption_status.stdout).contains("enabled") {
        log_audit_event(
            "COMPLIANCE_VIOLATION",
            "SYSTEM",
            "BellandeOS encryption is not enabled",
        )
        .await?;
    }

    // Check BellandeOS firewall configuration
    let firewall_status = Command::new("bellctl")
        .args(&["firewall", "status"])
        .output()
        .context("Failed to check firewall status")?;

    if !firewall_status.status.success() {
        log_audit_event(
            "COMPLIANCE_VIOLATION",
            "SYSTEM",
            "BellandeOS firewall is not properly configured",
        )
        .await?;
    }

    // Check security policies
    check_bellande_security_policies().await?;

    Ok(())
}

// Helper functions

async fn check_sysctl_settings() -> Result<()> {
    let sysctl_checks = [
        ("kernel.randomize_va_space", "2"),
        ("kernel.kptr_restrict", "2"),
        ("kernel.dmesg_restrict", "1"),
        ("kernel.yama.ptrace_scope", "1"),
        ("net.ipv4.conf.all.rp_filter", "1"),
        ("net.ipv4.conf.default.rp_filter", "1"),
    ];

    for (setting, expected_value) in &sysctl_checks {
        let output = Command::new("sysctl")
            .arg("-n")
            .arg(setting)
            .output()
            .context(format!("Failed to check sysctl setting: {}", setting))?;

        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if value != *expected_value {
            log_audit_event(
                "COMPLIANCE_VIOLATION",
                "SYSTEM",
                &format!(
                    "Incorrect sysctl setting {}: expected {}, got {}",
                    setting, expected_value, value
                ),
            )
            .await?;
        }
    }

    Ok(())
}

async fn check_password_policies() -> Result<()> {
    let login_defs_path = "/etc/login.defs";
    if Path::new(login_defs_path).exists() {
        let content = fs::read_to_string(login_defs_path).context("Failed to read login.defs")?;

        let checks = [
            ("PASS_MAX_DAYS", "90"),
            ("PASS_MIN_DAYS", "1"),
            ("PASS_MIN_LEN", "12"),
            ("PASS_WARN_AGE", "7"),
        ];

        for (setting, expected) in &checks {
            if !content.lines().any(|line| {
                line.starts_with(setting) && line.split_whitespace().nth(1) == Some(expected)
            }) {
                log_audit_event(
                    "COMPLIANCE_VIOLATION",
                    "SYSTEM",
                    &format!("Incorrect password policy setting: {}", setting),
                )
                .await?;
            }
        }
    }

    Ok(())
}

async fn check_core_dumps() -> Result<()> {
    let limits_conf = "/etc/security/limits.conf";
    if Path::new(limits_conf).exists() {
        let content = fs::read_to_string(limits_conf).context("Failed to read limits.conf")?;

        if !content.lines().any(|line| line.contains("* hard core 0")) {
            log_audit_event(
                "COMPLIANCE_VIOLATION",
                "SYSTEM",
                "Core dumps are not disabled",
            )
            .await?;
        }
    }

    Ok(())
}

async fn check_bellande_security_policies() -> Result<()> {
    let policies = [
        ("password-complexity", "high"),
        ("session-timeout", "enabled"),
        ("audit-level", "full"),
        ("network-isolation", "enforced"),
    ];

    for (policy, expected_value) in &policies {
        let output = Command::new("bellctl")
            .args(&["policy", "get", policy])
            .output()
            .context(format!("Failed to check policy: {}", policy))?;

        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if value != *expected_value {
            log_audit_event(
                "COMPLIANCE_VIOLATION",
                "SYSTEM",
                &format!(
                    "Incorrect security policy {}: expected {}, got {}",
                    policy, expected_value, value
                ),
            )
            .await?;
        }
    }

    Ok(())
}
async fn is_service_running(service: &str) -> Result<bool> {
    match std::env::consts::OS {
        "macos" => {
            let output = Command::new("launchctl")
                .args(&["list", service])
                .output()?;
            Ok(output.status.success())
        }
        "linux" => {
            let output = Command::new("systemctl")
                .args(&["is-active", service])
                .output()?;
            Ok(output.status.success())
        }
        "bellandeos" => {
            let output = Command::new("bellctl")
                .args(&["service", "status", service])
                .output()?;
            Ok(output.status.success())
        }
        _ => Ok(false),
    }
}

async fn check_firewall_status() -> Result<()> {
    match std::env::consts::OS {
        "macos" => {
            let output = Command::new("defaults")
                .args(&["read", "/Library/Preferences/com.apple.alf", "globalstate"])
                .output()
                .context("Failed to check macOS firewall status")?;

            if !String::from_utf8_lossy(&output.stdout).contains("1") {
                log_audit_event(
                    "COMPLIANCE_VIOLATION",
                    "SYSTEM",
                    "macOS firewall is not enabled",
                )
                .await?;
            }
        }
        "linux" => {
            let output = Command::new("ufw")
                .arg("status")
                .output()
                .context("Failed to check UFW status")?;

            if !String::from_utf8_lossy(&output.stdout).contains("Status: active") {
                log_audit_event(
                    "COMPLIANCE_VIOLATION",
                    "SYSTEM",
                    "UFW firewall is not active",
                )
                .await?;
            }
        }
        "bellandeos" => {
            let output = Command::new("bellctl")
                .args(&["firewall", "status"])
                .output()
                .context("Failed to check BellandeOS firewall status")?;

            if !String::from_utf8_lossy(&output.stdout).contains("enabled") {
                log_audit_event(
                    "COMPLIANCE_VIOLATION",
                    "SYSTEM",
                    "BellandeOS firewall is not enabled",
                )
                .await?;
            }
        }
        _ => warn!("Firewall checking not implemented for this OS"),
    }
    Ok(())
}

async fn check_network_encryption(network_requirements: &NetworkRequirements) -> Result<()> {
    // Check SSL/TLS versions
    check_ssl_versions(&network_requirements.required_protocols).await?;

    // Check SSH configuration
    check_ssh_configuration().await?;

    // Check encrypted protocols
    check_encrypted_protocols().await?;

    Ok(())
}

async fn check_ssl_versions(required_protocols: &[String]) -> Result<()> {
    match std::env::consts::OS {
        "macos" | "linux" | "bellandeos" => {
            let output = Command::new("openssl")
                .args(&["version"])
                .output()
                .context("Failed to check OpenSSL version")?;

            let version = String::from_utf8_lossy(&output.stdout);

            for protocol in required_protocols {
                if !version.contains(protocol) {
                    log_audit_event(
                        "COMPLIANCE_VIOLATION",
                        "SYSTEM",
                        &format!("Required protocol {} not available", protocol),
                    )
                    .await?;
                }
            }
        }
        _ => warn!("SSL version checking not implemented for this OS"),
    }
    Ok(())
}

async fn check_ssh_configuration() -> Result<()> {
    let ssh_config_path = match std::env::consts::OS {
        "macos" | "linux" => Path::new("/etc/ssh/sshd_config"),
        "bellandeos" => Path::new("/bell/security/ssh/sshd_config"),
        _ => return Ok(()),
    };

    if !ssh_config_path.exists() {
        log_audit_event(
            "COMPLIANCE_VIOLATION",
            "SYSTEM",
            "SSH configuration file not found",
        )
        .await?;
        return Ok(());
    }

    let file = File::open(ssh_config_path)?;
    let reader = BufReader::new(file);

    let required_settings = [
        ("PermitRootLogin", "no"),
        ("PasswordAuthentication", "no"),
        ("X11Forwarding", "no"),
        ("Protocol", "2"),
    ];

    for line in reader.lines() {
        let line = line?;
        for (setting, expected_value) in &required_settings {
            if line.starts_with(setting) && !line.contains(expected_value) {
                log_audit_event(
                    "COMPLIANCE_VIOLATION",
                    "SYSTEM",
                    &format!("SSH setting {} has incorrect value", setting),
                )
                .await?;
            }
        }
    }

    Ok(())
}

async fn check_encrypted_protocols() -> Result<()> {
    // Check for unencrypted protocols
    let unsafe_protocols = ["telnet", "ftp", "http"];

    let output = Command::new("netstat")
        .args(&["-tulpn"])
        .output()
        .context("Failed to check network protocols")?;

    let output_str = String::from_utf8_lossy(&output.stdout);

    for protocol in unsafe_protocols {
        if output_str.contains(protocol) {
            log_audit_event(
                "COMPLIANCE_VIOLATION",
                "SYSTEM",
                &format!("Unsafe protocol in use: {}", protocol),
            )
            .await?;
        }
    }

    Ok(())
}

async fn get_last_password_change(username: &str) -> Result<Option<String>> {
    match std::env::consts::OS {
        "macos" => {
            let output = Command::new("dscl")
                .args(&[
                    ".",
                    "-read",
                    &format!("/Users/{}", username),
                    "passwordLastSetTime",
                ])
                .output()?;
            Ok(Some(String::from_utf8_lossy(&output.stdout).to_string()))
        }
        "linux" => {
            let output = Command::new("chage").args(&["-l", username]).output()?;
            Ok(Some(String::from_utf8_lossy(&output.stdout).to_string()))
        }
        "bellandeos" => {
            let output = Command::new("bellctl")
                .args(&["user", "password-info", username])
                .output()?;
            Ok(Some(String::from_utf8_lossy(&output.stdout).to_string()))
        }
        _ => Ok(None),
    }
}

fn calculate_file_hash(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn load_file_hashes(path: &Path) -> Result<HashMap<PathBuf, String>> {
    if path.exists() {
        let file = File::open(path)?;
        Ok(serde_json::from_reader(file)?)
    } else {
        Ok(HashMap::new())
    }
}

fn save_file_hash(path: &Path, file_path: &Path, hash: &str) -> Result<()> {
    let mut hashes = load_file_hashes(path)?;
    hashes.insert(file_path.to_path_buf(), hash.to_string());
    let file = File::create(path)?;
    serde_json::to_writer_pretty(file, &hashes)?;
    Ok(())
}
