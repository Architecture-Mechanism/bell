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

use crate::audit::audit::log_audit_event;
use crate::config::config::Config;
use crate::user_privilege::user::User;
use anyhow::{Context, Result};
use argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand_core::OsRng;
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};
use totp_rs::TOTP;

pub struct Session {
    pub user: User,
    pub expiry: SystemTime,
}

pub struct RateLimiter {
    attempts: HashMap<String, Vec<Instant>>,
    max_attempts: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_attempts: usize, window: Duration) -> Self {
        RateLimiter {
            attempts: HashMap::new(),
            max_attempts,
            window,
        }
    }

    pub fn check(&mut self, key: &str) -> bool {
        let now = Instant::now();
        let attempts = self
            .attempts
            .entry(key.to_string())
            .or_insert_with(Vec::new);

        attempts.retain(|&t| now.duration_since(t) < self.window);

        if attempts.len() >= self.max_attempts {
            false
        } else {
            attempts.push(now);
            true
        }
    }
}

pub async fn authenticate_user(
    config: &Config,
    username: &str,
    password: &str,
    totp_code: &str,
    rate_limiter: &mut RateLimiter,
) -> Result<Option<User>> {
    if !rate_limiter.check(username) {
        log_audit_event("AUTHENTICATION_RATE_LIMIT", username, "Rate limit exceeded").await?;
        return Ok(None);
    }

    if let Some(user) = config.users.iter().find(|u| u.username == username) {
        if verify_password(&user.password_hash, password)? {
            let totp = TOTP::new(
                totp_rs::Algorithm::SHA1,
                6,
                1,
                30,
                user.totp_secret.as_bytes().to_vec(),
            )
            .context("Failed to create TOTP")?;

            if totp.check_current(totp_code)? {
                log_audit_event(
                    "AUTHENTICATION_SUCCESS",
                    &user.username,
                    "User authenticated successfully",
                )
                .await?;
                return Ok(Some(user.clone()));
            }
        }
    }

    log_audit_event("AUTHENTICATION_FAILURE", username, "Authentication failed").await?;
    Ok(None)
}

fn verify_password(hash: &str, password: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hash).context("Failed to parse password hash")?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .context("Failed to hash password")?
        .to_string();

    Ok(password_hash)
}
