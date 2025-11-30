use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use aws_config::Region;
use aws_credential_types::Credentials;
use aws_sdk_s3::{config::Builder as S3ConfigBuilder, primitives::ByteStream, Client as S3Client};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use sha2::Sha256;
use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tracing::{error, info, warn};

const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;

#[derive(Error, Debug)]
pub enum BackupError {
    #[error("pg_dump failed: {0}")]
    PgDumpFailed(String),
    #[error("pg_restore failed: {0}")]
    PgRestoreFailed(String),
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("S3 upload failed: {0}")]
    S3UploadFailed(String),
    #[error("S3 download failed: {0}")]
    S3DownloadFailed(String),
    #[error("S3 list failed: {0}")]
    S3ListFailed(String),
    #[error("S3 delete failed: {0}")]
    S3DeleteFailed(String),
    #[error("No backup found")]
    NoBackupFound,
    #[error("Database check failed: {0}")]
    DatabaseCheckFailed(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

#[derive(Clone)]
pub struct BackupConfig {
    // Postgres connection
    pub pg_host: String,
    pub pg_port: u16,
    pub pg_user: String,
    pub pg_password: String,
    pub pg_database: String,

    // S3-compatible storage (works with AWS S3, Cloudflare R2, MinIO, etc.)
    pub s3_endpoint: String,
    pub s3_bucket: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
    pub s3_region: String,

    // Backup settings
    pub backup_prefix: String,
    pub backup_interval_secs: u64,
    pub retention_count: Option<usize>, // Keep last N backups
    pub retention_days: Option<u64>,    // Or delete backups older than N days

    // Encryption (derived from MNEMONIC)
    pub mnemonic: Option<String>,
}

impl BackupConfig {
    pub fn from_env() -> Option<Self> {
        let s3_endpoint = std::env::var("BACKUP_S3_ENDPOINT").ok()?;
        let s3_bucket = std::env::var("BACKUP_S3_BUCKET").ok()?;
        let s3_access_key = std::env::var("BACKUP_S3_ACCESS_KEY").ok()?;
        let s3_secret_key = std::env::var("BACKUP_S3_SECRET_KEY").ok()?;

        Some(Self {
            pg_host: std::env::var("PG_HOST").unwrap_or_else(|_| "localhost".into()),
            pg_port: std::env::var("PG_PORT")
                .unwrap_or_else(|_| "5432".into())
                .parse()
                .unwrap_or(5432),
            pg_user: std::env::var("PG_USER").unwrap_or_else(|_| "postgres".into()),
            pg_password: std::env::var("PG_PASSWORD").unwrap_or_else(|_| "postgres".into()),
            pg_database: std::env::var("PG_DATABASE").unwrap_or_else(|_| "postgres".into()),

            s3_endpoint,
            s3_bucket,
            s3_access_key,
            s3_secret_key,
            s3_region: std::env::var("BACKUP_S3_REGION").unwrap_or_else(|_| "auto".into()),

            backup_prefix: std::env::var("BACKUP_PREFIX")
                .unwrap_or_else(|_| "pg-backup".into()),
            backup_interval_secs: std::env::var("BACKUP_INTERVAL_SECS")
                .unwrap_or_else(|_| "86400".into()) // Default: daily
                .parse()
                .unwrap_or(86400),
            retention_count: std::env::var("BACKUP_RETENTION_COUNT")
                .ok()
                .and_then(|s| s.parse().ok()),
            retention_days: std::env::var("BACKUP_RETENTION_DAYS")
                .ok()
                .and_then(|s| s.parse().ok()),

            mnemonic: std::env::var("MNEMONIC").ok(),
        })
    }

    pub fn is_enabled(&self) -> bool {
        !self.s3_endpoint.is_empty() && !self.s3_bucket.is_empty()
    }
}

/// Derives a 256-bit encryption key from the mnemonic using HKDF
fn derive_encryption_key(mnemonic: &str) -> [u8; KEY_SIZE] {
    let hk = Hkdf::<Sha256>::new(Some(b"pg-ecdsa-proxy-backup"), mnemonic.as_bytes());
    let mut key = [0u8; KEY_SIZE];
    hk.expand(b"backup-encryption-key", &mut key)
        .expect("HKDF expand failed");
    key
}

/// Encrypts data using AES-256-GCM with a random nonce
fn encrypt(data: &[u8], key: &[u8; KEY_SIZE]) -> Result<Vec<u8>, BackupError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| BackupError::EncryptionFailed(e.to_string()))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| BackupError::EncryptionFailed(e.to_string()))?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypts data that was encrypted with encrypt()
fn decrypt(encrypted: &[u8], key: &[u8; KEY_SIZE]) -> Result<Vec<u8>, BackupError> {
    if encrypted.len() < NONCE_SIZE {
        return Err(BackupError::EncryptionFailed("Data too short".into()));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| BackupError::EncryptionFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(&encrypted[..NONCE_SIZE]);
    let ciphertext = &encrypted[NONCE_SIZE..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| BackupError::EncryptionFailed(e.to_string()))
}

/// Creates an S3 client configured for the given endpoint
fn create_s3_client(config: &BackupConfig) -> S3Client {
    let credentials = Credentials::new(
        &config.s3_access_key,
        &config.s3_secret_key,
        None,
        None,
        "backup-credentials",
    );

    let s3_config = S3ConfigBuilder::new()
        .behavior_version_latest()
        .endpoint_url(&config.s3_endpoint)
        .region(Region::new(config.s3_region.clone()))
        .credentials_provider(credentials)
        .force_path_style(true) // Required for most S3-compatible services
        .build();

    S3Client::from_conf(s3_config)
}

/// Runs pg_dump and returns the backup data
async fn run_pg_dump(config: &BackupConfig) -> Result<Vec<u8>, BackupError> {
    // Try common pg_dump locations
    let pg_dump_path = if std::path::Path::new("/usr/local/bin/pg_dump").exists() {
        "/usr/local/bin/pg_dump"
    } else if std::path::Path::new("/usr/bin/pg_dump").exists() {
        "/usr/bin/pg_dump"
    } else {
        "pg_dump" // Fall back to PATH
    };
    
    let mut cmd = Command::new(pg_dump_path);
    cmd.env("PGPASSWORD", &config.pg_password)
        .arg("-h")
        .arg(&config.pg_host)
        .arg("-p")
        .arg(config.pg_port.to_string())
        .arg("-U")
        .arg(&config.pg_user)
        .arg("-d")
        .arg(&config.pg_database)
        .arg("-F")
        .arg("c") // Custom format (compressed)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| BackupError::PgDumpFailed(format!("Failed to spawn pg_dump: {}", e)))?;

    let mut stdout = child.stdout.take().unwrap();
    let mut backup_data = Vec::new();
    stdout
        .read_to_end(&mut backup_data)
        .await
        .map_err(|e| BackupError::PgDumpFailed(format!("Failed to read pg_dump output: {}", e)))?;

    let status = child
        .wait()
        .await
        .map_err(|e| BackupError::PgDumpFailed(format!("Failed to wait for pg_dump: {}", e)))?;

    if !status.success() {
        return Err(BackupError::PgDumpFailed(format!(
            "pg_dump exited with status: {}",
            status
        )));
    }

    Ok(backup_data)
}

/// Uploads encrypted backup to S3-compatible storage
async fn upload_backup(
    client: &S3Client,
    bucket: &str,
    key: &str,
    data: Vec<u8>,
) -> Result<(), BackupError> {
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from(data))
        .content_type("application/octet-stream")
        .send()
        .await
        .map_err(|e| BackupError::S3UploadFailed(e.to_string()))?;

    Ok(())
}

/// Lists backups with the given prefix
async fn list_backups(
    client: &S3Client,
    bucket: &str,
    prefix: &str,
) -> Result<Vec<(String, DateTime<Utc>)>, BackupError> {
    let response = client
        .list_objects_v2()
        .bucket(bucket)
        .prefix(prefix)
        .send()
        .await
        .map_err(|e| BackupError::S3ListFailed(e.to_string()))?;

    let mut backups = Vec::new();
    if let Some(contents) = response.contents {
        for obj in contents {
            if let (Some(key), Some(modified)) = (obj.key, obj.last_modified) {
                let dt = DateTime::from_timestamp(modified.secs(), modified.subsec_nanos())
                    .unwrap_or_default();
                backups.push((key, dt));
            }
        }
    }

    // Sort by date, newest first
    backups.sort_by(|a, b| b.1.cmp(&a.1));
    Ok(backups)
}

/// Deletes old backups based on retention policy
async fn cleanup_old_backups(client: &S3Client, config: &BackupConfig) -> Result<(), BackupError> {
    let backups = list_backups(client, &config.s3_bucket, &config.backup_prefix).await?;

    let mut to_delete = Vec::new();
    let now = Utc::now();

    for (i, (key, modified)) in backups.iter().enumerate() {
        let should_delete = match (config.retention_count, config.retention_days) {
            (Some(count), _) if i >= count => true,
            (_, Some(days)) => {
                let age = now.signed_duration_since(*modified);
                age.num_days() > days as i64
            }
            _ => false,
        };

        if should_delete {
            to_delete.push(key.clone());
        }
    }

    for key in to_delete {
        info!("Deleting old backup: {}", key);
        client
            .delete_object()
            .bucket(&config.s3_bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| BackupError::S3DeleteFailed(e.to_string()))?;
    }

    Ok(())
}

/// Performs a single backup operation
pub async fn perform_backup(config: &BackupConfig) -> Result<String, BackupError> {
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
    let backup_key = format!("{}/{}.backup.enc", config.backup_prefix, timestamp);

    info!("Starting backup to {}", backup_key);

    // Run pg_dump
    let backup_data = run_pg_dump(config).await?;
    info!("pg_dump completed, {} bytes", backup_data.len());

    // Encrypt if mnemonic is available
    let final_data = if let Some(ref mnemonic) = config.mnemonic {
        let key = derive_encryption_key(mnemonic);
        let encrypted = encrypt(&backup_data, &key)?;
        info!(
            "Backup encrypted, {} bytes -> {} bytes",
            backup_data.len(),
            encrypted.len()
        );
        encrypted
    } else {
        warn!("MNEMONIC not set, backup will NOT be encrypted!");
        backup_data
    };

    // Upload to S3
    let client = create_s3_client(config);
    upload_backup(&client, &config.s3_bucket, &backup_key, final_data).await?;
    info!("Backup uploaded to s3://{}/{}", config.s3_bucket, backup_key);

    // Cleanup old backups
    if config.retention_count.is_some() || config.retention_days.is_some() {
        if let Err(e) = cleanup_old_backups(&client, config).await {
            error!("Failed to cleanup old backups: {}", e);
        }
    }

    Ok(backup_key)
}

/// Starts the backup scheduler
pub async fn start_backup_scheduler(config: BackupConfig) {
    if !config.is_enabled() {
        info!("Backup not configured, skipping scheduler");
        return;
    }

    info!(
        "Starting backup scheduler, interval: {}s",
        config.backup_interval_secs
    );

    // Perform initial backup after a short delay
    tokio::time::sleep(Duration::from_secs(60)).await;

    loop {
        match perform_backup(&config).await {
            Ok(key) => info!("Backup completed: {}", key),
            Err(e) => error!("Backup failed: {}", e),
        }

        tokio::time::sleep(Duration::from_secs(config.backup_interval_secs)).await;
    }
}

/// Downloads a backup from S3
async fn download_backup(
    client: &S3Client,
    bucket: &str,
    key: &str,
) -> Result<Vec<u8>, BackupError> {
    let response = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .map_err(|e| BackupError::S3DownloadFailed(e.to_string()))?;

    let data = response
        .body
        .collect()
        .await
        .map_err(|e| BackupError::S3DownloadFailed(e.to_string()))?;

    Ok(data.into_bytes().to_vec())
}

/// Runs pg_restore to restore a backup
async fn run_pg_restore(config: &BackupConfig, backup_data: &[u8]) -> Result<(), BackupError> {
    // Try common pg_restore locations
    let pg_restore_path = if std::path::Path::new("/usr/local/bin/pg_restore").exists() {
        "/usr/local/bin/pg_restore"
    } else if std::path::Path::new("/usr/bin/pg_restore").exists() {
        "/usr/bin/pg_restore"
    } else {
        "pg_restore"
    };

    let mut cmd = Command::new(pg_restore_path);
    cmd.env("PGPASSWORD", &config.pg_password)
        .arg("-h")
        .arg(&config.pg_host)
        .arg("-p")
        .arg(config.pg_port.to_string())
        .arg("-U")
        .arg(&config.pg_user)
        .arg("-d")
        .arg(&config.pg_database)
        .arg("--clean")        // Drop existing objects before restore
        .arg("--if-exists")    // Don't error if objects don't exist
        .arg("--no-owner")     // Don't set ownership
        .arg("--no-privileges") // Don't restore privileges
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| BackupError::PgRestoreFailed(format!("Failed to spawn pg_restore: {}", e)))?;

    // Write backup data to stdin
    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin
            .write_all(backup_data)
            .await
            .map_err(|e| BackupError::PgRestoreFailed(format!("Failed to write to pg_restore: {}", e)))?;
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| BackupError::PgRestoreFailed(format!("Failed to wait for pg_restore: {}", e)))?;

    // pg_restore returns non-zero for warnings too, so we check stderr for actual errors
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore common warnings
        if stderr.contains("ERROR") && !stderr.contains("does not exist") {
            return Err(BackupError::PgRestoreFailed(format!(
                "pg_restore failed: {}",
                stderr
            )));
        }
    }

    Ok(())
}

/// Checks if the database has any user tables (empty = needs restore)
async fn is_database_empty(config: &BackupConfig) -> Result<bool, BackupError> {
    // Use psql to check for user tables
    let psql_path = if std::path::Path::new("/usr/local/bin/psql").exists() {
        "/usr/local/bin/psql"
    } else if std::path::Path::new("/usr/bin/psql").exists() {
        "/usr/bin/psql"
    } else {
        "psql"
    };

    let mut cmd = Command::new(psql_path);
    cmd.env("PGPASSWORD", &config.pg_password)
        .arg("-h")
        .arg(&config.pg_host)
        .arg("-p")
        .arg(config.pg_port.to_string())
        .arg("-U")
        .arg(&config.pg_user)
        .arg("-d")
        .arg(&config.pg_database)
        .arg("-t") // Tuples only
        .arg("-c")
        .arg("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE';")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd
        .output()
        .await
        .map_err(|e| BackupError::DatabaseCheckFailed(format!("Failed to run psql: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(BackupError::DatabaseCheckFailed(stderr.to_string()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let count: i32 = stdout.trim().parse().unwrap_or(0);
    
    Ok(count == 0)
}

/// Restores from the latest backup if database is empty
pub async fn restore_if_empty(config: &BackupConfig) -> Result<bool, BackupError> {
    if !config.is_enabled() {
        info!("Backup not configured, skipping restore check");
        return Ok(false);
    }

    // Check if database is empty
    info!("Checking if database needs restore...");
    let is_empty = is_database_empty(config).await?;

    if !is_empty {
        info!("Database has existing tables, skipping restore");
        return Ok(false);
    }

    info!("Database is empty, looking for backup to restore...");

    // List backups and get the latest one
    let client = create_s3_client(config);
    let backups = list_backups(&client, &config.s3_bucket, &config.backup_prefix).await?;

    if backups.is_empty() {
        info!("No backups found, starting fresh");
        return Ok(false);
    }

    let (latest_key, latest_date) = &backups[0];
    info!("Found latest backup: {} ({})", latest_key, latest_date);

    // Download the backup
    info!("Downloading backup...");
    let encrypted_data = download_backup(&client, &config.s3_bucket, latest_key).await?;
    info!("Downloaded {} bytes", encrypted_data.len());

    // Decrypt if mnemonic is available
    let backup_data = if let Some(ref mnemonic) = config.mnemonic {
        info!("Decrypting backup...");
        let key = derive_encryption_key(mnemonic);
        let decrypted = decrypt(&encrypted_data, &key)?;
        info!("Decrypted {} bytes", decrypted.len());
        decrypted
    } else {
        warn!("MNEMONIC not set, assuming backup is not encrypted");
        encrypted_data
    };

    // Restore the backup
    info!("Restoring backup to database...");
    run_pg_restore(config, &backup_data).await?;
    info!("Restore completed successfully!");

    Ok(true)
}

/// Derive encryption key for external use (e.g., restore scripts)
#[allow(dead_code)]
pub fn get_encryption_key_from_mnemonic(mnemonic: &str) -> [u8; KEY_SIZE] {
    derive_encryption_key(mnemonic)
}

