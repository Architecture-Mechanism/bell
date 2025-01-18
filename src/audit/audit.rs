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

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Local, Utc};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditConfig {
    log_file: PathBuf,
    database_file: PathBuf,
    max_log_size: u64,
    rotation_count: u32,
    alert_email: String,
    smtp_server: String,
    smtp_port: u16,
    smtp_username: String,
    smtp_password: String,
    critical_events: Vec<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        let os_specific_path = match std::env::consts::OS {
            "macos" => PathBuf::from("/var/log/bell"),
            "linux" => PathBuf::from("/var/log/bell"),
            "bellandeos" => PathBuf::from("/bell/log"),
            _ => PathBuf::from("./log"),
        };

        Self {
            log_file: os_specific_path.join("audit.log"),
            database_file: os_specific_path.join("audit.db"),
            max_log_size: 10 * 1024 * 1024, // 10MB
            rotation_count: 5,
            alert_email: "admin@bellande-architecture-mechanism-research-innovation-center.org"
                .to_string(),
            smtp_server: "smtp.bellande-architecture-mechanism-research-innovation-center.org"
                .to_string(),
            smtp_port: 587,
            smtp_username: "alerts@bellande-architecture-mechanism.org".to_string(),
            smtp_password: "your_secure_password".to_string(),
            critical_events: vec![
                "AUTHENTICATION_FAILURE".to_string(),
                "PERMISSION_DENIED".to_string(),
                "SUSPICIOUS_ACTIVITY".to_string(),
                "SECURITY_BREACH".to_string(),
                "SYSTEM_MODIFICATION".to_string(),
            ],
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    timestamp: DateTime<Utc>,
    user: String,
    event: String,
    details: String,
    system: String,
    process_id: u32,
    severity: EventSeverity,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum EventSeverity {
    Info,
    Warning,
    Critical,
    Emergency,
}

pub async fn log_audit_event(event: &str, user: &str, details: &str) -> Result<()> {
    let config = AuditConfig::default();
    let audit_event = create_audit_event(event, user, details);

    // Ensure log directory exists
    if let Some(parent) = config.log_file.parent() {
        fs::create_dir_all(parent).context("Failed to create log directory")?;
    }

    // Check log rotation
    check_and_rotate_logs(&config).await?;

    // Write to log file
    write_to_log_file(&config, &audit_event).await?;

    // Write to database
    log_to_database(&config, &audit_event).await?;

    // Send alert if critical
    if is_critical_event(&config, event) {
        send_alert(&config, &audit_event).await?;
    }

    Ok(())
}

fn create_audit_event(event: &str, user: &str, details: &str) -> AuditEvent {
    AuditEvent {
        timestamp: Utc::now(),
        user: user.to_string(),
        event: event.to_string(),
        details: details.to_string(),
        system: std::env::consts::OS.to_string(),
        process_id: std::process::id(),
        severity: determine_severity(event),
    }
}

async fn write_to_log_file(config: &AuditConfig, event: &AuditEvent) -> Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&config.log_file)
        .context("Failed to open audit log file")?;

    let log_entry = format!(
        "{} - User: {} - Event: {} - Details: {} - System: {} - PID: {} - Severity: {:?}\n",
        event.timestamp.with_timezone(&Local),
        event.user,
        event.event,
        event.details,
        event.system,
        event.process_id,
        event.severity
    );

    file.write_all(log_entry.as_bytes())
        .context("Failed to write to audit log")?;

    Ok(())
}

async fn log_to_database(config: &AuditConfig, event: &AuditEvent) -> Result<()> {
    let conn = Connection::open(&config.database_file).context("Failed to open database")?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            user TEXT NOT NULL,
            event TEXT NOT NULL,
            details TEXT NOT NULL,
            system TEXT NOT NULL,
            process_id INTEGER NOT NULL,
            severity TEXT NOT NULL
        )",
        [],
    )
    .context("Failed to create audit_log table")?;

    conn.execute(
        "INSERT INTO audit_log (timestamp, user, event, details, system, process_id, severity)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            event.timestamp.to_rfc3339(),
            event.user,
            event.event,
            event.details,
            event.system,
            event.process_id,
            format!("{:?}", event.severity)
        ],
    )
    .context("Failed to insert log entry into database")?;

    Ok(())
}

fn is_critical_event(config: &AuditConfig, event: &str) -> bool {
    config.critical_events.contains(&event.to_string())
}

fn determine_severity(event: &str) -> EventSeverity {
    match event {
        "AUTHENTICATION_FAILURE" | "PERMISSION_DENIED" => EventSeverity::Warning,
        "SUSPICIOUS_ACTIVITY" | "SECURITY_BREACH" => EventSeverity::Critical,
        "SYSTEM_MODIFICATION" => EventSeverity::Emergency,
        _ => EventSeverity::Info,
    }
}

async fn send_alert(config: &AuditConfig, event: &AuditEvent) -> Result<()> {
    let email = Message::builder()
        .from(config.smtp_username.parse().context("Invalid from address")?)
        .to(config.alert_email.parse().context("Invalid to address")?)
        .subject(format!("Critical Security Alert: {}", event.event))
        .header(ContentType::TEXT_PLAIN)
        .body(format!(
            "Critical security event detected:\n\nTimestamp: {}\nUser: {}\nEvent: {}\nDetails: {}\nSystem: {}\nProcess ID: {}\nSeverity: {:?}",
            event.timestamp.with_timezone(&Local),
            event.user,
            event.event,
            event.details,
            event.system,
            event.process_id,
            event.severity
        ))
        .context("Failed to build email")?;

    let creds = Credentials::new(config.smtp_username.clone(), config.smtp_password.clone());

    let mailer = SmtpTransport::relay(&config.smtp_server)
        .context("Failed to create SMTP transport")?
        .credentials(creds)
        .port(config.smtp_port)
        .build();

    mailer.send(&email).context("Failed to send email")?;

    Ok(())
}

async fn check_and_rotate_logs(config: &AuditConfig) -> Result<()> {
    let metadata = fs::metadata(&config.log_file)?;

    if metadata.len() >= config.max_log_size {
        for i in (1..config.rotation_count).rev() {
            let current = config.log_file.with_extension(format!("log.{}", i));
            let next = config.log_file.with_extension(format!("log.{}", i + 1));
            if current.exists() {
                fs::rename(current, next)?;
            }
        }

        let backup = config.log_file.with_extension("log.1");
        fs::rename(&config.log_file, backup)?;
        fs::File::create(&config.log_file)?;
    }

    Ok(())
}
