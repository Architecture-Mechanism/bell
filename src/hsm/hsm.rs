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
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as base64, Engine as _};
use log::{info, warn};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const KEY_ROTATION_DAYS: u64 = 30;

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyStore {
    label: String,
    key_id: [u8; 8],
    encrypted_key: Vec<u8>,
    created_at: SystemTime,
    rotated_at: Option<SystemTime>,
    fingerprint: String,
    metadata: KeyMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyMetadata {
    algorithm: String,
    key_type: KeyType,
    usage: KeyUsage,
    platform: String,
}

#[derive(Debug, Serialize, Deserialize)]
enum KeyType {
    Master,
    Data,
    Signing,
    Authentication,
}

#[derive(Debug, Serialize, Deserialize)]
enum KeyUsage {
    Encryption,
    Decryption,
    Both,
}

pub struct SecureStorage {
    key_store: Arc<RwLock<HashMap<String, KeyStore>>>,
    storage_path: PathBuf,
}

// Platform-specific implementations
#[cfg(unix)]
fn set_secure_permissions(options: &mut OpenOptions) -> &mut OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600)
}

fn encode_sensitive_data(data: &[u8]) -> String {
    base64.encode(data)
}

fn decode_sensitive_data(data: &str) -> Result<Vec<u8>> {
    base64
        .decode(data.trim())
        .context("Failed to decode base64 data")
}

impl SecureStorage {
    pub async fn new() -> Result<Self> {
        let storage_path = get_platform_storage_path()?;
        ensure_secure_directory(&storage_path)?;

        let key_store = Arc::new(RwLock::new(HashMap::new()));
        let storage = SecureStorage {
            key_store,
            storage_path,
        };

        storage.initialize().await?;
        Ok(storage)
    }

    async fn initialize(&self) -> Result<()> {
        // Load existing keys
        self.load_keys().await?;

        // Check for key rotation
        self.check_key_rotation().await?;

        // Initialize platform-specific secure storage
        match std::env::consts::OS {
            "macos" => self.initialize_keychain().await?,
            "linux" => self.initialize_keyring().await?,
            "bellandeos" => self.initialize_bellande_secure_store().await?,
            _ => warn!("No platform-specific secure storage available"),
        }

        Ok(())
    }

    async fn load_key_from_keyring(&self, line: &str) -> Result<Option<KeyStore>> {
        let label = match line.split("bell_key_").nth(1) {
            Some(l) => l,
            None => return Ok(None),
        };

        let output = std::process::Command::new("keyctl")
            .args(&["read", "user", &format!("bell_key_{}", label)])
            .output()
            .context("Failed to read key from keyring")?;

        if output.status.success() {
            let encoded_data = String::from_utf8_lossy(&output.stdout);
            let key_data = decode_sensitive_data(&encoded_data)?;
            let key_store: KeyStore =
                serde_json::from_slice(&key_data).context("Failed to deserialize key store")?;
            Ok(Some(key_store))
        } else {
            Ok(None)
        }
    }

    async fn load_key_from_keychain(&self, line: &str) -> Result<Option<KeyStore>> {
        let label = match line.split("bell_key_").nth(1) {
            Some(l) => l,
            None => return Ok(None),
        };

        let output = std::process::Command::new("security")
            .args(&[
                "find-generic-password",
                "-s",
                &format!("bell_key_{}", label),
                "-w",
            ])
            .output()
            .context("Failed to read key from keychain")?;

        if output.status.success() {
            let encoded_data = String::from_utf8_lossy(&output.stdout);
            let key_data = decode_sensitive_data(&encoded_data)?;
            let key_store: KeyStore =
                serde_json::from_slice(&key_data).context("Failed to deserialize key store")?;
            Ok(Some(key_store))
        } else {
            Ok(None)
        }
    }

    async fn load_key_from_bellande(&self, line: &str) -> Result<Option<KeyStore>> {
        let label = match line.split("bell_key_").nth(1) {
            Some(l) => l,
            None => return Ok(None),
        };

        let output = std::process::Command::new("bellctl")
            .args(&["secure-store", "get", &format!("bell_key_{}", label)])
            .output()
            .context("Failed to read key from BellandeOS secure store")?;

        if output.status.success() {
            let encoded_data = String::from_utf8_lossy(&output.stdout);
            let key_data = decode_sensitive_data(&encoded_data)?;
            let key_store: KeyStore =
                serde_json::from_slice(&key_data).context("Failed to deserialize key store")?;
            Ok(Some(key_store))
        } else {
            Ok(None)
        }
    }

    async fn load_master_key_from_keychain(&self) -> Result<Key<Aes256Gcm>> {
        let output = std::process::Command::new("security")
            .args(&["find-generic-password", "-s", "bell_master_key", "-w"])
            .output()
            .context("Failed to read from keychain")?;

        if output.status.success() {
            let encoded = String::from_utf8_lossy(&output.stdout);
            let key_data = decode_sensitive_data(&encoded)?;
            if key_data.len() != KEY_SIZE {
                return Err(anyhow::anyhow!("Invalid key length"));
            }
            let key = Key::<Aes256Gcm>::from_slice(&key_data);
            Ok(key.clone())
        } else {
            self.generate_and_store_master_key().await
        }
    }

    async fn load_master_key_from_bellande(&self) -> Result<Key<Aes256Gcm>> {
        let output = std::process::Command::new("bellctl")
            .args(&["secure-store", "get", "bell_master_key"])
            .output()
            .context("Failed to read from BellandeOS secure store")?;

        if output.status.success() {
            let encoded = String::from_utf8_lossy(&output.stdout);
            let key_data = decode_sensitive_data(&encoded)?;
            if key_data.len() != KEY_SIZE {
                return Err(anyhow::anyhow!("Invalid key length"));
            }
            let key = Key::<Aes256Gcm>::from_slice(&key_data);
            Ok(key.clone())
        } else {
            self.generate_and_store_master_key().await
        }
    }

    async fn save_keys(&self) -> Result<()> {
        let store = self.key_store.read().await;

        for key_store in store.values() {
            let key_data = serde_json::to_string(key_store)?;
            let encoded_data = encode_sensitive_data(key_data.as_bytes());

            match std::env::consts::OS {
                "macos" => {
                    std::process::Command::new("security")
                        .args(&[
                            "add-generic-password",
                            "-s",
                            &format!("bell_key_{}", key_store.label),
                            "-w",
                            &encoded_data,
                        ])
                        .output()
                        .context("Failed to store in keychain")?;
                }
                "linux" => {
                    std::process::Command::new("keyctl")
                        .args(&[
                            "add",
                            "user",
                            &format!("bell_key_{}", key_store.label),
                            &encoded_data,
                            "@u",
                        ])
                        .output()
                        .context("Failed to store in keyring")?;
                }
                "bellandeos" => {
                    std::process::Command::new("bellctl")
                        .args(&[
                            "secure-store",
                            "set",
                            &format!("bell_key_{}", key_store.label),
                            &encoded_data,
                        ])
                        .output()
                        .context("Failed to store in BellandeOS secure store")?;
                }
                _ => {
                    let key_file = self.storage_path.join(format!("{}.key", key_store.label));
                    fs::write(key_file, &encoded_data)?;
                }
            }
        }

        Ok(())
    }

    pub async fn generate_key(
        &self,
        label: &str,
        key_type: KeyType,
        usage: KeyUsage,
    ) -> Result<Vec<u8>> {
        let mut key = vec![0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);

        let key_id = rand::random::<[u8; 8]>();
        let master_key = self.load_master_key().await?;

        let encrypted_key = self.encrypt_with_master_key(&master_key, &key).await?;
        let fingerprint = calculate_key_fingerprint(&key);

        let key_store = KeyStore {
            label: label.to_string(),
            key_id,
            encrypted_key,
            created_at: SystemTime::now(),
            rotated_at: None,
            fingerprint,
            metadata: KeyMetadata {
                algorithm: "AES-256-GCM".to_string(),
                key_type,
                usage,
                platform: std::env::consts::OS.to_string(),
            },
        };

        // Store in platform-specific secure storage
        self.store_key_in_platform_storage(&key_store).await?;

        // Update in-memory store
        let mut store = self.key_store.write().await;
        store.insert(label.to_string(), key_store);

        // Save to disk
        self.save_keys().await?;

        Ok(key_id.to_vec())
    }

    pub async fn encrypt_data(&self, data: &str) -> Result<Vec<u8>> {
        let master_key = self.load_master_key().await?;
        let cipher = Aes256Gcm::new(&master_key);

        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        let nonce = Nonce::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(nonce, data.as_bytes())
            .context("Failed to encrypt data")?;

        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(nonce);
        result.extend_from_slice(&ciphertext);

        log_crypto_operation("ENCRYPT", &result).await?;
        Ok(result)
    }

    pub async fn decrypt_data(&self, data: &[u8]) -> Result<String> {
        if data.len() < NONCE_SIZE {
            anyhow::bail!("Invalid encrypted data");
        }

        let master_key = self.load_master_key().await?;
        let cipher = Aes256Gcm::new(&master_key);

        let nonce = Nonce::from_slice(&data[..NONCE_SIZE]);
        let ciphertext = &data[NONCE_SIZE..];

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .context("Failed to decrypt data")?;

        log_crypto_operation("DECRYPT", data).await?;

        String::from_utf8(plaintext).context("Failed to convert decrypted data to string")
    }

    async fn load_master_key_from_keyring(&self) -> Result<Key<Aes256Gcm>> {
        let output = std::process::Command::new("keyctl")
            .args(&["read", "user", "bell_master_key"])
            .output()
            .context("Failed to read from keyring")?;

        if output.status.success() {
            let encoded = String::from_utf8_lossy(&output.stdout);
            let key_data = decode_sensitive_data(&encoded)?;
            if key_data.len() != KEY_SIZE {
                return Err(anyhow::anyhow!("Invalid key length"));
            }
            let key = Key::<Aes256Gcm>::from_slice(&key_data);
            Ok(key.clone())
        } else {
            self.generate_and_store_master_key().await
        }
    }

    async fn load_master_key(&self) -> Result<Key<Aes256Gcm>> {
        match std::env::consts::OS {
            "macos" => self.load_master_key_from_keychain().await,
            "linux" => self.load_master_key_from_keyring().await,
            "bellandeos" => self.load_master_key_from_bellande().await,
            _ => self.load_master_key_from_file().await,
        }
    }

    async fn load_master_key_from_file(&self) -> Result<Key<Aes256Gcm>> {
        let master_key_path = self.storage_path.join("master.key");

        if master_key_path.exists() {
            let mut file =
                File::open(&master_key_path).context("Failed to open master key file")?;

            let mut key_bytes = [0u8; KEY_SIZE];
            file.read_exact(&mut key_bytes)
                .context("Failed to read master key")?;

            let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
            Ok(key.clone())
        } else {
            self.generate_and_store_master_key().await
        }
    }

    async fn encrypt_with_master_key(
        &self,
        master_key: &Key<Aes256Gcm>,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(master_key);
        let nonce = Nonce::from_slice(&[0u8; NONCE_SIZE]);
        cipher
            .encrypt(nonce, data)
            .context("Failed to encrypt with master key")
    }

    async fn check_key_rotation(&self) -> Result<()> {
        let mut store = self.key_store.write().await;
        let now = SystemTime::now();

        for key_store in store.values_mut() {
            let last_rotation = key_store.rotated_at.unwrap_or(key_store.created_at);
            if now.duration_since(last_rotation)?.as_secs() > KEY_ROTATION_DAYS * 24 * 60 * 60 {
                let mut new_key = vec![0u8; KEY_SIZE];
                OsRng.fill_bytes(&mut new_key);

                let master_key = self.load_master_key().await?;
                key_store.encrypted_key =
                    self.encrypt_with_master_key(&master_key, &new_key).await?;
                key_store.rotated_at = Some(now);
                key_store.fingerprint = calculate_key_fingerprint(&new_key);

                self.store_key_in_platform_storage(key_store).await?;
            }
        }

        Ok(())
    }

    // Platform-specific implementations
    async fn initialize_keychain(&self) -> Result<()> {
        let output = std::process::Command::new("security")
            .args(&["create-keychain", "bell.keychain"])
            .output()
            .context("Failed to create keychain")?;

        if !output.status.success() {
            warn!("Keychain already exists or creation failed");
        }

        Ok(())
    }

    async fn initialize_keyring(&self) -> Result<()> {
        let output = std::process::Command::new("keyctl")
            .args(&["new_session"])
            .output()
            .context("Failed to create keyring session")?;

        if !output.status.success() {
            warn!("Keyring session creation failed");
        }

        Ok(())
    }

    async fn initialize_bellande_secure_store(&self) -> Result<()> {
        let output = std::process::Command::new("bellctl")
            .args(&["secure-store", "init"])
            .output()
            .context("Failed to initialize BellandeOS secure store")?;

        if !output.status.success() {
            warn!("BellandeOS secure store initialization failed");
        }

        Ok(())
    }

    async fn generate_and_store_master_key(&self) -> Result<Key<Aes256Gcm>> {
        let mut key_bytes = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key_bytes);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes).clone();
        let encoded_key = encode_sensitive_data(&key_bytes);

        match std::env::consts::OS {
            "macos" => {
                std::process::Command::new("security")
                    .args(&[
                        "add-generic-password",
                        "-s",
                        "bell_master_key",
                        "-w",
                        &encoded_key,
                    ])
                    .output()
                    .context("Failed to store in keychain")?;
            }
            "linux" => {
                std::process::Command::new("keyctl")
                    .args(&["add", "user", "bell_master_key", &encoded_key, "@u"])
                    .output()
                    .context("Failed to store in keyring")?;
            }
            "bellandeos" => {
                std::process::Command::new("bellctl")
                    .args(&["secure-store", "set", "bell_master_key", &encoded_key])
                    .output()
                    .context("Failed to store in BellandeOS secure store")?;
            }
            _ => {
                self.store_master_key_to_file(&key_bytes).await?;
            }
        }

        Ok(key)
    }

    async fn store_master_key_to_file(&self, key: &[u8]) -> Result<()> {
        let master_key_path = self.storage_path.join("master.key");

        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        let mut file = set_secure_permissions(&mut options)
            .open(&master_key_path)
            .context("Failed to create master key file")?;

        file.write_all(key).context("Failed to write master key")?;
        file.sync_all().context("Failed to sync master key file")?;

        Ok(())
    }

    async fn store_key_in_platform_storage(&self, key_store: &KeyStore) -> Result<()> {
        let key_data = serde_json::to_string(key_store)?;
        let encoded_data = encode_sensitive_data(key_data.as_bytes());

        match std::env::consts::OS {
            "macos" => self.store_key_in_keychain(key_store, &encoded_data).await?,
            "linux" => self.store_key_in_keyring(key_store, &encoded_data).await?,
            "bellandeos" => self.store_key_in_bellande(key_store, &encoded_data).await?,
            _ => self.store_key_in_file(key_store, &encoded_data).await?,
        }

        Ok(())
    }

    async fn store_key_in_keychain(&self, key_store: &KeyStore, encoded_data: &str) -> Result<()> {
        let output = std::process::Command::new("security")
            .args(&[
                "add-generic-password",
                "-s",
                &format!("bell_key_{}", key_store.label),
                "-w",
                encoded_data,
            ])
            .output()
            .context("Failed to store key in keychain")?;

        if !output.status.success() {
            // Try to delete existing entry first and retry
            let _ = std::process::Command::new("security")
                .args(&[
                    "delete-generic-password",
                    "-s",
                    &format!("bell_key_{}", key_store.label),
                ])
                .output();

            std::process::Command::new("security")
                .args(&[
                    "add-generic-password",
                    "-s",
                    &format!("bell_key_{}", key_store.label),
                    "-w",
                    encoded_data,
                ])
                .output()
                .context("Failed to store key in keychain after deletion")?;
        }

        Ok(())
    }

    async fn store_key_in_keyring(&self, key_store: &KeyStore, encoded_data: &str) -> Result<()> {
        // First, try to remove any existing key
        let _ = std::process::Command::new("keyctl")
            .args(&["unlink", &format!("bell_key_{}", key_store.label), "@u"])
            .output();

        let output = std::process::Command::new("keyctl")
            .args(&[
                "add",
                "user",
                &format!("bell_key_{}", key_store.label),
                encoded_data,
                "@u",
            ])
            .output()
            .context("Failed to store key in keyring")?;

        if !output.status.success() {
            anyhow::bail!("Failed to store key in keyring: {:?}", output);
        }

        Ok(())
    }

    async fn store_key_in_bellande(&self, key_store: &KeyStore, encoded_data: &str) -> Result<()> {
        let output = std::process::Command::new("bellctl")
            .args(&[
                "secure-store",
                "set",
                &format!("bell_key_{}", key_store.label),
                encoded_data,
            ])
            .output()
            .context("Failed to store key in BellandeOS secure store")?;

        if !output.status.success() {
            // Try to delete and retry
            let _ = std::process::Command::new("bellctl")
                .args(&[
                    "secure-store",
                    "delete",
                    &format!("bell_key_{}", key_store.label),
                ])
                .output();

            std::process::Command::new("bellctl")
                .args(&[
                    "secure-store",
                    "set",
                    &format!("bell_key_{}", key_store.label),
                    encoded_data,
                ])
                .output()
                .context("Failed to store key in BellandeOS secure store after deletion")?;
        }

        Ok(())
    }

    async fn store_key_in_file(&self, key_store: &KeyStore, encoded_data: &str) -> Result<()> {
        let key_file = self.storage_path.join(format!("{}.key", key_store.label));

        // Create a temporary file first
        let temp_file = key_file.with_extension("tmp");

        // Write to temporary file
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        let mut file = set_secure_permissions(&mut options)
            .open(&temp_file)
            .context("Failed to create temporary key file")?;

        file.write_all(encoded_data.as_bytes())
            .context("Failed to write key data")?;

        file.sync_all().context("Failed to sync key file")?;

        // Atomically rename temporary file to final location
        fs::rename(&temp_file, &key_file).context("Failed to save key file")?;

        Ok(())
    }

    async fn load_keys(&self) -> Result<()> {
        let mut store = self.key_store.write().await;

        match std::env::consts::OS {
            "macos" => {
                let output = std::process::Command::new("security")
                    .args(&["dump-keychain"])
                    .output()
                    .context("Failed to dump keychain")?;

                if output.status.success() {
                    for line in String::from_utf8_lossy(&output.stdout).lines() {
                        if line.contains("bell_key_") {
                            if let Some(key_store) = self.load_key_from_keychain(line).await? {
                                store.insert(key_store.label.clone(), key_store);
                            }
                        }
                    }
                }
            }
            "linux" => {
                let output = std::process::Command::new("keyctl")
                    .args(&["list", "@u"])
                    .output()
                    .context("Failed to list keyring")?;

                if output.status.success() {
                    for line in String::from_utf8_lossy(&output.stdout).lines() {
                        if line.contains("bell_key_") {
                            if let Some(key_store) = self.load_key_from_keyring(line).await? {
                                store.insert(key_store.label.clone(), key_store);
                            }
                        }
                    }
                }
            }
            "bellandeos" => {
                let output = std::process::Command::new("bellctl")
                    .args(&["secure-store", "list"])
                    .output()
                    .context("Failed to list BellandeOS secure store")?;

                if output.status.success() {
                    for line in String::from_utf8_lossy(&output.stdout).lines() {
                        if line.contains("bell_key_") {
                            if let Some(key_store) = self.load_key_from_bellande(line).await? {
                                store.insert(key_store.label.clone(), key_store);
                            }
                        }
                    }
                }
            }
            _ => {
                // Fallback to file-based storage
                if let Ok(entries) = fs::read_dir(&self.storage_path) {
                    for entry in entries {
                        if let Ok(entry) = entry {
                            if let Some(filename) = entry.file_name().to_str() {
                                if filename.ends_with(".key") {
                                    if let Ok(key_data) = fs::read_to_string(entry.path()) {
                                        match serde_json::from_str::<KeyStore>(&key_data) {
                                            Ok(key_store) => {
                                                store.insert(key_store.label.clone(), key_store);
                                            }
                                            Err(err) => {
                                                warn!("Failed to deserialize key store: {}", err);
                                                continue;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

fn get_platform_storage_path() -> Result<PathBuf> {
    let path = match std::env::consts::OS {
        "macos" => PathBuf::from("/Library/Application Support/bell/secure"),
        "linux" => PathBuf::from("/var/lib/bell/secure"),
        "bellandeos" => PathBuf::from("/bell/secure/storage"),
        _ => {
            let mut path = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            path.push("secure");
            path
        }
    };

    Ok(path)
}

fn ensure_secure_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
    }

    Ok(())
}

fn calculate_key_fingerprint(key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key);
    format!("{:x}", hasher.finalize())
}

async fn log_crypto_operation(operation: &str, data: &[u8]) -> Result<()> {
    let fingerprint = calculate_key_fingerprint(data);
    info!(
        "Crypto operation: {} - Size: {} bytes - Fingerprint: {}",
        operation,
        data.len(),
        fingerprint
    );
    Ok(())
}

pub async fn encrypt_data(data: &str) -> anyhow::Result<String> {
    let storage = SecureStorage::new().await?;
    let encrypted = storage.encrypt_data(data).await?;
    Ok(base64::engine::general_purpose::STANDARD.encode(&encrypted))
}

pub async fn decrypt_data(encrypted_data: &str) -> anyhow::Result<String> {
    let storage = SecureStorage::new().await?;
    let data = base64::engine::general_purpose::STANDARD.decode(encrypted_data)?;
    storage.decrypt_data(&data).await
}
