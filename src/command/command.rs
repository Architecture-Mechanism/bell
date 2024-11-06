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
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use tokio::process::Command as TokioCommand;

use anyhow::{Context, Result};
use nix::unistd::{Gid, Uid};
use serde::{Deserialize, Serialize};
use syscallz::{Context as SyscallContext, Syscall};
use tokio::time::timeout;

use crate::audit::audit::log_audit_event;
use crate::authentication_compliance::authentication::Session;
use crate::config::config::Config;
use crate::network::network::{is_network_allowed, isolate_network, restore_network};
use crate::user_privilege::privilege::{PrivilegeLevel, PrivilegeManager};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandConfig {
    dangerous_patterns: HashSet<String>,
    allowed_paths: Vec<PathBuf>,
    max_execution_time: Duration,
    sandbox_enabled: bool,
    network_isolation_required: bool,
    max_output_size: usize,
    log_output: bool,
}

impl Default for CommandConfig {
    fn default() -> Self {
        let allowed_paths = match std::env::consts::OS {
            "macos" => vec![
                PathBuf::from("/usr/bin"),
                PathBuf::from("/usr/local/bin"),
                PathBuf::from("/opt/homebrew/bin"),
            ],
            "linux" => vec![
                PathBuf::from("/usr/bin"),
                PathBuf::from("/usr/local/bin"),
                PathBuf::from("/bin"),
            ],
            "bellandeos" => vec![
                PathBuf::from("/bell/bin"),
                PathBuf::from("/bell/usr/bin"),
                PathBuf::from("/bell/local/bin"),
            ],
            _ => vec![],
        };

        let mut dangerous_patterns = HashSet::new();
        dangerous_patterns.insert("rm -rf /*".to_string());
        dangerous_patterns.insert("chmod 777".to_string());
        dangerous_patterns.insert("dd if=/dev/zero".to_string());
        dangerous_patterns.insert("mkfs".to_string());
        dangerous_patterns.insert("> /dev/sda".to_string());
        dangerous_patterns.insert(":(){ :|:& };:".to_string()); // Fork bomb
        dangerous_patterns.insert("sudo rm".to_string());
        dangerous_patterns.insert("> /dev/null".to_string());

        CommandConfig {
            dangerous_patterns,
            allowed_paths,
            max_execution_time: Duration::from_secs(300),
            sandbox_enabled: true,
            network_isolation_required: true,
            max_output_size: 1024 * 1024,
            log_output: true,
        }
    }
}

// Create a wrapper that implements Debug
struct SandboxContext {
    inner: SyscallContext,
}

impl std::fmt::Debug for SandboxContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxContext")
            .field("inner", &"SyscallContext")
            .finish()
    }
}

impl SandboxContext {
    fn new(context: SyscallContext) -> Self {
        Self { inner: context }
    }

    fn load(&self) -> Result<()> {
        self.inner
            .load()
            .map_err(|e| anyhow::anyhow!("Failed to load sandbox: {}", e))
    }

    fn allow_syscall(&mut self, syscall: Syscall) -> Result<()> {
        self.inner
            .allow_syscall(syscall)
            .map_err(|e| anyhow::anyhow!("Failed to allow syscall: {}", e))
    }
}

#[derive(Debug)]
struct CommandContext {
    command: String,
    args: Vec<String>,
    privilege_level: PrivilegeLevel,
    username: String,
    start_time: SystemTime,
    sandbox: Option<SandboxContext>,
    config: CommandConfig,
}

#[derive(Debug, Clone)]
struct DangerousPattern {
    pattern: String,
    description: String,
}

impl From<(&str, &str)> for DangerousPattern {
    fn from((pattern, description): (&str, &str)) -> Self {
        DangerousPattern {
            pattern: pattern.to_string(),
            description: description.to_string(),
        }
    }
}

// Implementation for command validation and execution
pub async fn run_command_with_privilege(
    session: &Session,
    command: &str,
    args: &[String],
    required_privilege: PrivilegeLevel,
    config: &Config,
    privilege_manager: &PrivilegeManager,
) -> Result<()> {
    let cmd_config = CommandConfig::default();

    // Validate input
    validate_command_input(command, args)?;

    // Check privileges and session
    check_session_and_permissions(
        session,
        command,
        args,
        required_privilege,
        config,
        privilege_manager,
        &cmd_config, // Add the command config parameter
    )
    .await?;

    // Create and execute command context
    let ctx = create_command_context(command, args, required_privilege, session, &cmd_config)?;

    execute_command_safely(ctx).await
}

fn validate_command_input(command: &str, args: &[String]) -> Result<()> {
    if command.is_empty() {
        return Err(anyhow::anyhow!("Command cannot be empty"));
    }

    // Check for null bytes and other dangerous characters
    if command.contains('\0') || args.iter().any(|arg| arg.contains('\0')) {
        return Err(anyhow::anyhow!("Command contains invalid characters"));
    }

    // Validate command path
    let command_path = PathBuf::from(command);
    if !command_path.is_absolute() {
        return Err(anyhow::anyhow!("Command must use absolute path"));
    }

    Ok(())
}

async fn check_session_and_permissions(
    session: &Session,
    command: &str,
    args: &[String],
    required_privilege: PrivilegeLevel,
    config: &Config,
    privilege_manager: &PrivilegeManager,
    cmd_config: &CommandConfig,
) -> Result<()> {
    // Check session state
    check_session_state(session, command, args).await?;

    // Check permissions
    check_command_permissions(
        session,
        command,
        args,
        required_privilege,
        config,
        privilege_manager,
    )
    .await?;

    // Check network access if required by command config
    if cmd_config.network_isolation_required {
        check_network_access(config, session, command, args).await?;
    }

    Ok(())
}

async fn check_session_state(session: &Session, command: &str, args: &[String]) -> Result<()> {
    // Check session expiry
    if SystemTime::now() > session.expiry {
        log_audit_event(
            "SESSION_EXPIRED",
            &session.user.username,
            &format!(
                "Attempted to run command with expired session: {} {:?}",
                command, args
            ),
        )
        .await?;
        return Err(anyhow::anyhow!(
            "Session expired. Please authenticate again."
        ));
    }

    // Check that user exists and is valid
    if session.user.username.is_empty() {
        log_audit_event(
            "INVALID_SESSION",
            "unknown",
            &format!(
                "Attempted to run command without valid user: {} {:?}",
                command, args
            ),
        )
        .await?;
        return Err(anyhow::anyhow!("Invalid session: no user associated"));
    }

    Ok(())
}

async fn check_command_permissions(
    session: &Session,
    command: &str,
    args: &[String],
    required_privilege: PrivilegeLevel,
    config: &Config,
    privilege_manager: &PrivilegeManager,
) -> Result<bool> {
    // Check base user privileges
    if !privilege_manager
        .check_permission(&session.user, required_privilege, config)
        .await?
    {
        log_audit_event(
            "PERMISSION_DENIED",
            &session.user.username,
            &format!(
                "Insufficient privileges for command: {} {:?}, required: {:?}",
                command, args, required_privilege
            ),
        )
        .await?;
        return Ok(false); // Return Ok(false) instead of Err
    }

    // Check if user belongs to required groups
    let has_required_group = session.user.groups.iter().any(|group| {
        config
            .groups
            .iter()
            .any(|g| &g.name == group && g.permissions.contains(&required_privilege.to_string()))
    });

    if !has_required_group && required_privilege > session.user.privilege {
        log_audit_event(
            "GROUP_PERMISSION_DENIED",
            &session.user.username,
            &format!(
                "User lacks required group membership for command: {} {:?}",
                command, args
            ),
        )
        .await?;
        return Ok(false); // Return Ok(false) instead of Err
    }

    Ok(true) // Return Ok(true) if all checks pass
}

async fn check_network_access(
    config: &Config,
    session: &Session,
    command: &str,
    args: &[String],
) -> Result<bool> {
    // Use is_network_allowed directly with the config
    if !is_network_allowed(config).await? {
        log_audit_event(
            "NETWORK_DENIED",
            &session.user.username,
            &format!("Network access denied for: {} {:?}", command, args),
        )
        .await?;
        return Ok(false);
    }

    Ok(true)
}

async fn execute_command_safely(ctx: CommandContext) -> Result<()> {
    // Log command execution start
    log_audit_event(
        "COMMAND_START",
        &ctx.username,
        &format!("Executing: {} {:?}", ctx.command, ctx.args),
    )
    .await?;

    // Check for dangerous patterns
    check_dangerous_patterns(&ctx).await?;

    // Apply sandbox if enabled
    if let Some(ref sandbox) = ctx.sandbox {
        sandbox.load().context("Failed to load sandbox")?;
    }

    // Drop privileges if necessary
    if ctx.privilege_level != PrivilegeLevel::Bell {
        drop_privileges().context("Failed to drop privileges")?;
    }

    // Isolate network if required
    let network_isolated = if ctx.config.network_isolation_required {
        isolate_network().await?;
        true
    } else {
        false
    };

    // Execute command with timeout
    let result = execute_command_with_timeout(&ctx).await;

    // Restore network if it was isolated
    if network_isolated {
        restore_network().await?;
    }

    // Handle command result
    match result {
        Ok(output) => process_command_output(&ctx, &output).await?,
        Err(e) => {
            log_audit_event(
                "COMMAND_FAILED",
                &ctx.username,
                &format!("Command failed: {} - Error: {}", ctx.command, e),
            )
            .await?;
            return Err(e);
        }
    }

    Ok(())
}

fn create_command_context(
    command: &str,
    args: &[String],
    privilege_level: PrivilegeLevel,
    session: &Session,
    cmd_config: &CommandConfig,
) -> Result<CommandContext> {
    Ok(CommandContext {
        command: command.to_string(),
        args: args.to_vec(),
        privilege_level,
        username: session.user.username.clone(),
        start_time: SystemTime::now(),
        sandbox: if cmd_config.sandbox_enabled {
            Some(create_sandbox()?)
        } else {
            None
        },
        config: cmd_config.clone(),
    })
}

async fn execute_command_with_timeout(ctx: &CommandContext) -> Result<std::process::Output> {
    // Create tokio command
    let mut command = TokioCommand::new(&ctx.command);
    command.args(&ctx.args);

    // Run with timeout
    let output = timeout(ctx.config.max_execution_time, command.output())
        .await
        .context("Command execution timed out")?
        .context("Command execution failed")?;

    Ok(output)
}

async fn process_command_output(ctx: &CommandContext, output: &std::process::Output) -> Result<()> {
    // Check output size limits
    if output.stdout.len() > ctx.config.max_output_size
        || output.stderr.len() > ctx.config.max_output_size
    {
        log_audit_event(
            "COMMAND_OUTPUT_TOO_LARGE",
            &ctx.username,
            &format!(
                "Output size exceeds limit of {} bytes",
                ctx.config.max_output_size
            ),
        )
        .await?;
        return Err(anyhow::anyhow!("Command output exceeds size limit"));
    }

    // Process stderr if present
    if !output.stderr.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        log_audit_event(
            "COMMAND_ERROR",
            &ctx.username,
            &format!("Command produced error output: {}", stderr),
        )
        .await?;
    }

    // Process stdout if logging is enabled
    if ctx.config.log_output && !output.stdout.is_empty() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        log_audit_event(
            "COMMAND_OUTPUT",
            &ctx.username,
            &format!("Command output: {}", stdout),
        )
        .await?;
    }

    // Check exit status
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Command failed with exit code: {}",
            output.status.code().unwrap_or(-1)
        ));
    }

    Ok(())
}

fn create_sandbox() -> Result<SandboxContext> {
    let mut ctx = SyscallContext::init()?;

    use syscallz::Syscall;

    // Essential system calls
    let essential_syscalls = [
        Syscall::read,
        Syscall::write,
        Syscall::exit,
        Syscall::exit_group,
        Syscall::brk,
        Syscall::arch_prctl,
    ];

    // File operations
    let file_syscalls = [
        Syscall::open,
        Syscall::openat,
        Syscall::close,
        Syscall::access,
        Syscall::getcwd,
        Syscall::lseek,
        Syscall::stat,
        Syscall::fstat,
        Syscall::lstat,
        Syscall::readlink,
    ];

    // Memory management
    let memory_syscalls = [
        Syscall::mmap,
        Syscall::munmap,
        Syscall::mprotect,
        Syscall::mremap,
    ];

    // Process management
    let process_syscalls = [
        Syscall::clone,
        Syscall::fork,
        Syscall::execve,
        Syscall::kill,
        Syscall::wait4,
        Syscall::getpid,
        Syscall::getppid,
        Syscall::getuid,
        Syscall::geteuid,
    ];

    // Allow the syscalls
    for syscall in essential_syscalls
        .iter()
        .chain(file_syscalls.iter())
        .chain(memory_syscalls.iter())
        .chain(process_syscalls.iter())
    {
        ctx.allow_syscall(*syscall)
            .with_context(|| format!("Failed to add syscall rule: {:?}", syscall))?;
    }

    Ok(SandboxContext::new(ctx))
}
fn drop_privileges() -> Result<()> {
    let nobody_uid = Uid::from_raw(65534); // nobody user
    let nobody_gid = Gid::from_raw(65534); // nobody group

    // Clear supplementary groups first
    nix::unistd::setgroups(&[]).context("Failed to clear supplementary groups")?;

    // Drop group privileges
    nix::unistd::setresgid(nobody_gid, nobody_gid, nobody_gid)
        .context("Failed to drop group privileges")?;

    // Drop user privileges
    nix::unistd::setresuid(nobody_uid, nobody_uid, nobody_uid)
        .context("Failed to drop user privileges")?;

    Ok(())
}

async fn check_dangerous_patterns(ctx: &CommandContext) -> Result<()> {
    let full_command = format!("{} {}", ctx.command, ctx.args.join(" "));

    // Check against dangerous patterns
    for pattern in &ctx.config.dangerous_patterns {
        if full_command.contains(pattern) {
            log_audit_event(
                "DANGEROUS_COMMAND",
                &ctx.username,
                &format!("Dangerous pattern detected: {}", pattern),
            )
            .await?;
            return Err(anyhow::anyhow!("Dangerous command pattern detected"));
        }
    }

    // OS-specific pattern checks
    match std::env::consts::OS {
        "macos" => check_macos_specific_patterns(ctx, &full_command).await?,
        "linux" => check_linux_specific_patterns(ctx, &full_command).await?,
        "bellandeos" => check_bellande_specific_patterns(ctx, &full_command).await?,
        _ => {}
    }

    Ok(())
}

fn convert_patterns<const N: usize>(patterns: [(&str, &str); N]) -> Vec<DangerousPattern> {
    patterns.into_iter().map(DangerousPattern::from).collect()
}

async fn check_macos_specific_patterns(ctx: &CommandContext, command: &str) -> Result<()> {
    let dangerous_patterns = convert_patterns([
        ("diskutil eraseDisk", "Disk erasure attempt"),
        ("csrutil disable", "SIP disable attempt"),
        ("nvram", "NVRAM modification attempt"),
        ("kextload", "Kernel extension loading attempt"),
        ("spctl --master-disable", "Gatekeeper disable attempt"),
    ]);
    check_patterns(ctx, command, &dangerous_patterns).await
}

async fn check_linux_specific_patterns(ctx: &CommandContext, command: &str) -> Result<()> {
    let dangerous_patterns = convert_patterns([
        ("modprobe", "Kernel module loading attempt"),
        ("insmod", "Kernel module insertion attempt"),
        ("mount", "File system mounting attempt"),
        ("sysctl -w", "Sysctl modification attempt"),
        ("echo 1 > /proc/sys", "Sysctl modification attempt"),
        ("iptables -F", "Firewall flush attempt"),
    ]);
    check_patterns(ctx, command, &dangerous_patterns).await
}

async fn check_bellande_specific_patterns(ctx: &CommandContext, command: &str) -> Result<()> {
    let dangerous_patterns = convert_patterns([
        ("bellctl system reset", "System reset attempt"),
        ("bellctl security disable", "Security disable attempt"),
        ("bellctl kernel modify", "Kernel modification attempt"),
        ("bellctl firewall disable", "Firewall disable attempt"),
        ("bellctl audit stop", "Audit stop attempt"),
    ]);
    check_patterns(ctx, command, &dangerous_patterns).await
}

async fn check_patterns(
    ctx: &CommandContext,
    command: &str,
    patterns: &[DangerousPattern],
) -> Result<()> {
    for pattern in patterns {
        if command.contains(&pattern.pattern) {
            log_audit_event("DANGEROUS_COMMAND", &ctx.username, &pattern.description).await?;
            return Err(anyhow::anyhow!("Dangerous command pattern detected"));
        }
    }
    Ok(())
}

async fn check_macos_patterns(ctx: &CommandContext, command: &str) -> Result<()> {
    let patterns = vec![
        DangerousPattern {
            pattern: "diskutil eraseDisk".to_string(),
            description: "Disk erasure attempt".to_string(),
        },
        DangerousPattern {
            pattern: "csrutil disable".to_string(),
            description: "SIP disable attempt".to_string(),
        },
        DangerousPattern {
            pattern: "nvram".to_string(),
            description: "NVRAM modification attempt".to_string(),
        },
        DangerousPattern {
            pattern: "kextload".to_string(),
            description: "Kernel extension loading attempt".to_string(),
        },
    ];

    check_patterns(ctx, command, &patterns).await
}

async fn check_linux_patterns(ctx: &CommandContext, command: &str) -> Result<()> {
    let patterns = vec![
        DangerousPattern {
            pattern: "modprobe".to_string(),
            description: "Kernel module loading attempt".to_string(),
        },
        DangerousPattern {
            pattern: "insmod".to_string(),
            description: "Kernel module insertion attempt".to_string(),
        },
        DangerousPattern {
            pattern: "mount".to_string(),
            description: "File system mounting attempt".to_string(),
        },
        DangerousPattern {
            pattern: "sysctl -w".to_string(),
            description: "Sysctl modification attempt".to_string(),
        },
    ];

    check_patterns(ctx, command, &patterns).await
}

async fn check_bellande_patterns(ctx: &CommandContext, command: &str) -> Result<()> {
    let patterns = vec![
        DangerousPattern {
            pattern: "bellctl system reset".to_string(),
            description: "System reset attempt".to_string(),
        },
        DangerousPattern {
            pattern: "bellctl security disable".to_string(),
            description: "Security disable attempt".to_string(),
        },
        DangerousPattern {
            pattern: "bellctl kernel modify".to_string(),
            description: "Kernel modification attempt".to_string(),
        },
    ];

    check_patterns(ctx, command, &patterns).await
}
