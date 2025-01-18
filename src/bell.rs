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

mod audit;
mod authentication_compliance;
mod command;
mod config;
mod hsm;
mod network;
mod user_privilege;

use std::time::{Duration, SystemTime};
use structopt::StructOpt;
use tokio;

use crate::authentication_compliance::authentication::{authenticate_user, RateLimiter, Session};
use crate::command::command::run_command_with_privilege;
use crate::config::config::Config;
use crate::user_privilege::privilege::{PrivilegeConfig, PrivilegeLevel, PrivilegeManager};
use crate::user_privilege::user::{
    add_user, add_user_to_group, change_password, change_privilege, remove_user,
    remove_user_from_group,
};

#[derive(StructOpt, Debug)]
#[structopt(name = "bell", about = "Privilege escalation system")]
enum Opt {
    #[structopt(name = "run")]
    Run {
        #[structopt(short, long)]
        privilege_level: String,
        #[structopt(short, long)]
        command: String,
        #[structopt(short, long)]
        args: Vec<String>,
    },
    #[structopt(name = "user")]
    User {
        #[structopt(subcommand)]
        cmd: UserCommand,
    },
}

#[derive(StructOpt, Debug)]
enum UserCommand {
    Add {
        username: String,
        #[structopt(short, long)]
        privilege: String,
    },
    Remove {
        username: String,
    },
    ChangePassword {
        username: String,
    },
    ChangePrivilege {
        username: String,
        privilege: String,
    },
    AddToGroup {
        username: String,
        group: String,
    },
    RemoveFromGroup {
        username: String,
        group: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    log4rs::init_file("log4rs.yaml", Default::default())?;

    let opt = Opt::from_args();

    let mut config = Config::load()?;
    let privilege_config = PrivilegeConfig::default();
    let mut rate_limiter = RateLimiter::new(5, Duration::from_secs(60));
    let privilege_manager = PrivilegeManager::new(privilege_config);

    match opt {
        Opt::Run {
            privilege_level,
            command,
            args,
        } => {
            println!("Enter username:");
            let mut username = String::new();
            std::io::stdin().read_line(&mut username)?;
            let username = username.trim();

            println!("Enter password:");
            let mut password = String::new();
            std::io::stdin().read_line(&mut password)?;
            let password = password.trim();

            println!("Enter TOTP code:");
            let mut totp_code = String::new();
            std::io::stdin().read_line(&mut totp_code)?;
            let totp_code = totp_code.trim();

            if let Some(user) =
                authenticate_user(&config, username, password, totp_code, &mut rate_limiter).await?
            {
                let session = Session {
                    user: user.clone(),
                    expiry: SystemTime::now() + Duration::from_secs(config.session_duration),
                };

                let privilege_level = match privilege_level.as_str() {
                    "bell" => PrivilegeLevel::Bell,
                    "root" => PrivilegeLevel::Root,
                    "admin" => PrivilegeLevel::Administrator,
                    "user" => PrivilegeLevel::User,
                    _ => {
                        println!(
                            "Invalid privilege level. Use 'bell', 'root', 'admin', or 'user'."
                        );
                        return Ok(());
                    }
                };

                run_command_with_privilege(
                    &session,
                    &command,
                    &args,
                    privilege_level,
                    &config,
                    &privilege_manager,
                )
                .await?;
            } else {
                println!("Authentication failed.");
            }
        }
        Opt::User { cmd } => match cmd {
            UserCommand::Add {
                username,
                privilege,
            } => {
                println!("Enter new password:");
                let mut password = String::new();
                std::io::stdin().read_line(&mut password)?;
                let password = password.trim();

                let privilege_level = match privilege.as_str() {
                    "bell" => PrivilegeLevel::Bell,
                    "root" => PrivilegeLevel::Root,
                    "admin" | "administrator" => PrivilegeLevel::Administrator,
                    "user" => PrivilegeLevel::User,
                    _ => {
                        println!(
                            "Invalid privilege level. Use 'bell', 'root', 'admin', or 'user'."
                        );
                        return Ok(());
                    }
                };
                add_user(&mut config, &username, password, privilege_level).await?;
            }
            UserCommand::Remove { username } => {
                remove_user(&mut config, &username).await?;
            }
            UserCommand::ChangePassword { username } => {
                println!("Enter new password:");
                let mut password = String::new();
                std::io::stdin().read_line(&mut password)?;
                let password = password.trim();

                change_password(&mut config, &username, password).await?;
            }
            UserCommand::ChangePrivilege {
                username,
                privilege,
            } => {
                let privilege_level = match privilege.as_str() {
                    "bell" => PrivilegeLevel::Bell,
                    "root" => PrivilegeLevel::Root,
                    "admin" | "administrator" => PrivilegeLevel::Administrator,
                    "user" => PrivilegeLevel::User,
                    _ => {
                        println!(
                            "Invalid privilege level. Use 'bell', 'root', 'admin', or 'user'."
                        );
                        return Ok(());
                    }
                };
                change_privilege(&mut config, &username, privilege_level).await?;
            }
            UserCommand::AddToGroup { username, group } => {
                add_user_to_group(&mut config, &username, &group).await?;
            }
            UserCommand::RemoveFromGroup { username, group } => {
                remove_user_from_group(&mut config, &username, &group).await?;
            }
        },
    }

    Ok(())
}
