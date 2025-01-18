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

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ipnetwork::Ipv4Network;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::config::config::Config;

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub interface: String,
    pub namespace: String,
    pub allowed_ports: Vec<u16>,
    pub dns_servers: Vec<String>,
    pub retry_attempts: u32,
    pub retry_delay: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            interface: get_default_interface(),
            namespace: "bell_isolated".to_string(),
            allowed_ports: vec![53, 80, 443], // DNS, HTTP, HTTPS
            dns_servers: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
            retry_attempts: 3,
            retry_delay: 1,
        }
    }
}

#[derive(Debug)]
struct NetworkCommands {
    down_cmd: Vec<String>,
    up_cmd: Vec<String>,
    flush_cmd: Vec<String>,
    firewall_cmd: Vec<String>,
}

impl NetworkCommands {
    fn new() -> Self {
        match std::env::consts::OS {
            "macos" => Self {
                down_cmd: vec!["ifconfig".into(), "{interface}".into(), "down".into()],
                up_cmd: vec!["ifconfig".into(), "{interface}".into(), "up".into()],
                flush_cmd: vec![
                    "ifconfig".into(),
                    "{interface}".into(),
                    "inet".into(),
                    "0".into(),
                ],
                firewall_cmd: vec!["pfctl".into(), "-f".into(), "/etc/pf.conf".into()],
            },
            "linux" => Self {
                down_cmd: vec![
                    "ip".into(),
                    "link".into(),
                    "set".into(),
                    "{interface}".into(),
                    "down".into(),
                ],
                up_cmd: vec![
                    "ip".into(),
                    "link".into(),
                    "set".into(),
                    "{interface}".into(),
                    "up".into(),
                ],
                flush_cmd: vec![
                    "ip".into(),
                    "addr".into(),
                    "flush".into(),
                    "dev".into(),
                    "{interface}".into(),
                ],
                firewall_cmd: vec!["iptables".into(), "-F".into()],
            },
            "bellandeos" => Self {
                down_cmd: vec![
                    "bellctl".into(),
                    "net".into(),
                    "down".into(),
                    "{interface}".into(),
                ],
                up_cmd: vec![
                    "bellctl".into(),
                    "net".into(),
                    "up".into(),
                    "{interface}".into(),
                ],
                flush_cmd: vec![
                    "bellctl".into(),
                    "net".into(),
                    "flush".into(),
                    "{interface}".into(),
                ],
                firewall_cmd: vec!["bellctl".into(), "firewall".into(), "reset".into()],
            },
            _ => Self {
                down_cmd: vec![],
                up_cmd: vec![],
                flush_cmd: vec![],
                firewall_cmd: vec![],
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AuditEvent {
    timestamp: DateTime<Utc>,
    event_type: String,
    user: String,
    message: String,
    source_ip: Option<String>,
    severity: AuditSeverity,
}

#[derive(Debug, Serialize, Deserialize)]
enum AuditSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl Default for AuditSeverity {
    fn default() -> Self {
        AuditSeverity::Info
    }
}

pub async fn isolate_network() -> Result<()> {
    let config = NetworkConfig::default();
    let commands = NetworkCommands::new();

    info!(
        "Starting network isolation process for {}",
        std::env::consts::OS
    );

    let down_cmd = replace_interface_placeholder(&commands.down_cmd, &config.interface);
    if let Some((cmd, args)) = down_cmd.split_first() {
        run_command(cmd, args).await?;
    }

    let flush_cmd = replace_interface_placeholder(&commands.flush_cmd, &config.interface);
    if let Some((cmd, args)) = flush_cmd.split_first() {
        run_command(cmd, args).await?;
    }

    setup_firewall_rules(&config).await?;

    log_audit_event(
        "NETWORK_ISOLATION",
        "SYSTEM",
        &format!(
            "Network isolated on {}: {}",
            std::env::consts::OS,
            config.interface
        ),
    )
    .await?;

    Ok(())
}

pub async fn restore_network() -> Result<()> {
    let config = NetworkConfig::default();
    let commands = NetworkCommands::new();

    info!(
        "Starting network restoration process for {}",
        std::env::consts::OS
    );

    let up_cmd = replace_interface_placeholder(&commands.up_cmd, &config.interface);
    if let Some((cmd, args)) = up_cmd.split_first() {
        run_command(cmd, args).await?;
    }

    let mut attempts = 0;
    while attempts < config.retry_attempts {
        match request_dhcp_lease(&config.interface).await {
            Ok(_) => break,
            Err(e) => {
                warn!("DHCP request failed, attempt {}: {}", attempts + 1, e);
                if attempts + 1 == config.retry_attempts {
                    return Err(e);
                }
                sleep(Duration::from_secs(config.retry_delay)).await;
                attempts += 1;
            }
        }
    }

    log_audit_event(
        "NETWORK_RESTORATION",
        "SYSTEM",
        &format!(
            "Network restored on {}: {}",
            std::env::consts::OS,
            config.interface
        ),
    )
    .await?;

    Ok(())
}

async fn run_command(cmd: &str, args: &[String]) -> Result<()> {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .context(format!("Failed to run command: {} {:?}", cmd, args))?;

    if !status.success() {
        error!("Command failed: {} {:?}", cmd, args);
        anyhow::bail!("Command failed with status: {}", status);
    }

    Ok(())
}

fn replace_interface_placeholder(cmd: &[String], interface: &str) -> Vec<String> {
    cmd.iter()
        .map(|s| s.replace("{interface}", interface))
        .collect()
}

async fn setup_firewall_rules(config: &NetworkConfig) -> Result<()> {
    match std::env::consts::OS {
        "macos" => setup_pf_firewall(config).await?,
        "linux" => setup_iptables_firewall(config).await?,
        "bellandeos" => setup_bell_firewall(config).await?,
        _ => anyhow::bail!("Unsupported operating system"),
    }
    Ok(())
}

async fn setup_pf_firewall(config: &NetworkConfig) -> Result<()> {
    let pf_rules = generate_pf_rules(config);
    std::fs::write("/etc/pf.conf", pf_rules).context("Failed to write PF configuration")?;

    run_command("pfctl", &["-f".to_string(), "/etc/pf.conf".to_string()])
        .await
        .context("Failed to load PF rules")?;
    run_command("pfctl", &["-e".to_string()])
        .await
        .context("Failed to enable PF firewall")?;

    Ok(())
}

async fn setup_iptables_firewall(config: &NetworkConfig) -> Result<()> {
    run_command("iptables", &["-F".to_string()]).await?;

    for port in &config.allowed_ports {
        let port_str = port.to_string();
        let args = vec![
            "-A".to_string(),
            "OUTPUT".to_string(),
            "-p".to_string(),
            "tcp".to_string(),
            "--dport".to_string(),
            port_str,
            "-j".to_string(),
            "ACCEPT".to_string(),
        ];
        run_command("iptables", &args).await?;
    }

    run_command(
        "iptables",
        &["-P".to_string(), "OUTPUT".to_string(), "DROP".to_string()],
    )
    .await
}

async fn setup_bell_firewall(config: &NetworkConfig) -> Result<()> {
    run_command("bellctl", &["firewall".to_string(), "reset".to_string()]).await?;

    for port in &config.allowed_ports {
        let port_str = port.to_string();
        let args = vec![
            "firewall".to_string(),
            "allow".to_string(),
            "port".to_string(),
            port_str,
        ];
        run_command("bellctl", &args).await?;
    }

    run_command(
        "bellctl",
        &["firewall".to_string(), "default-deny".to_string()],
    )
    .await
}

fn generate_pf_rules(config: &NetworkConfig) -> String {
    let mut rules = String::new();

    rules.push_str("# Generated PF rules\n");
    rules.push_str("set skip on lo0\n");
    rules.push_str("set block-policy drop\n");
    rules.push_str("\n# Default deny all\n");
    rules.push_str("block all\n\n");

    // Allow DNS to specified servers
    rules.push_str("# Allow DNS to specified servers\n");
    for dns in &config.dns_servers {
        rules.push_str(&format!("pass out proto udp to {} port 53\n", dns));
    }

    // Allow specified ports
    rules.push_str("\n# Allow specified outbound ports\n");
    for port in &config.allowed_ports {
        rules.push_str(&format!("pass out proto tcp to any port {}\n", port));
    }

    // Security rules
    rules.push_str("\n# Security rules\n");
    rules.push_str("block in quick from urpf-failed\n");
    rules.push_str("block in quick from { 10/8, 172.16/12, 192.168/16 } to any\n");
    rules.push_str("block in quick from any to { 10/8, 172.16/12, 192.168/16 }\n");

    rules
}

fn get_default_interface() -> String {
    match std::env::consts::OS {
        "macos" => "en0".to_string(),
        "linux" => "eth0".to_string(),
        "bellandeos" => "bell0".to_string(),
        _ => "unknown".to_string(),
    }
}

async fn request_dhcp_lease(interface: &str) -> Result<()> {
    match std::env::consts::OS {
        "macos" => {
            run_command(
                "ipconfig",
                &["set".to_string(), interface.to_string(), "DHCP".to_string()],
            )
            .await?;
        }
        "linux" => {
            run_command("dhclient", &[interface.to_string()]).await?;
        }
        "bellandeos" => {
            run_command(
                "bellctl",
                &["net".to_string(), "dhcp".to_string(), interface.to_string()],
            )
            .await?;
        }
        _ => anyhow::bail!("Unsupported operating system"),
    }
    Ok(())
}

async fn log_audit_event(event_type: &str, user: &str, message: &str) -> Result<()> {
    let event = AuditEvent {
        timestamp: Utc::now(),
        event_type: event_type.to_string(),
        user: user.to_string(),
        message: message.to_string(),
        source_ip: get_source_ip().await,
        severity: get_event_severity(event_type),
    };

    info!(
        "Audit: {} - {}: {}",
        event.event_type, event.user, event.message
    );
    write_audit_log(&event).await?;

    if matches!(event.severity, AuditSeverity::Critical) {
        flush_audit_log().await?;
    }

    Ok(())
}

async fn get_source_ip() -> Option<String> {
    match local_ip_address::local_ip() {
        Ok(ip) => Some(ip.to_string()),
        Err(_) => None,
    }
}

fn get_event_severity(event_type: &str) -> AuditSeverity {
    match event_type {
        "NETWORK_ISOLATION" | "NETWORK_RESTORATION" => AuditSeverity::Warning,
        "NETWORK_CHECK" => AuditSeverity::Info,
        "SECURITY_VIOLATION" | "NETWORK_ATTACK" => AuditSeverity::Critical,
        _ => AuditSeverity::Info,
    }
}

async fn write_audit_log(event: &AuditEvent) -> Result<()> {
    let log_path = get_audit_log_path();

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .context(format!("Failed to open audit log file: {:?}", log_path))?;

    let log_entry = serde_json::to_string(&event).context("Failed to serialize audit event")?;

    writeln!(file, "{}", log_entry).context("Failed to write to audit log")?;

    Ok(())
}

async fn flush_audit_log() -> Result<()> {
    let log_path = get_audit_log_path();

    let mut file = OpenOptions::new()
        .append(true)
        .open(&log_path)
        .context("Failed to open audit log for flushing")?;

    file.sync_all()
        .context("Failed to flush audit log to disk")?;

    Ok(())
}

fn get_audit_log_path() -> PathBuf {
    match std::env::consts::OS {
        "macos" => PathBuf::from("/var/log/security/audit.log"),
        "linux" => PathBuf::from("/var/log/audit/audit.log"),
        "bellandeos" => PathBuf::from("/bell/logs/audit/system.log"),
        _ => PathBuf::from("audit.log"),
    }
}

pub async fn rotate_audit_logs() -> Result<()> {
    let log_path = get_audit_log_path();

    if let Ok(metadata) = std::fs::metadata(&log_path) {
        // Rotate if file is larger than 10MB
        if metadata.len() > 10_000_000 {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let backup_path = log_path.with_extension(format!("log.{}", timestamp));

            std::fs::rename(&log_path, &backup_path).context("Failed to rotate audit log")?;

            File::create(&log_path).context("Failed to create new audit log after rotation")?;

            log_audit_event(
                "AUDIT_LOG_ROTATION",
                "SYSTEM",
                &format!("Rotated audit log to {:?}", backup_path),
            )
            .await?;
        }
    }

    Ok(())
}

pub async fn is_network_allowed(config: &Config) -> Result<bool> {
    let local_ip = local_ip_address::local_ip().context("Failed to get local IP address")?;

    for network_str in &config.allowed_networks {
        let network: Ipv4Network = network_str
            .parse()
            .context("Failed to parse network configuration")?;

        if let IpAddr::V4(ipv4) = local_ip {
            if network.contains(ipv4) {
                log_audit_event(
                    "NETWORK_CHECK",
                    "SYSTEM",
                    &format!("Network allowed: {}", local_ip),
                )
                .await?;
                return Ok(true);
            }
        }
    }

    log_audit_event(
        "NETWORK_CHECK",
        "SYSTEM",
        &format!("Network denied: {}", local_ip),
    )
    .await?;
    Ok(false)
}
