// SPDX-License-Identifier: AGPL-3.0-or-later
//! Private local files for the listener's plaintext record store.
//! Authorization happens in server.rs before any record access.
use crate::{MAX_BODY, MAX_DB, Result, fail, protocol};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub const MAX_RECORDS: usize = 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecord {
    key: String,
    value_base64: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    format: String,
    profile_id: String,
    revision: u64,
    records_sha256: String,
    records: Vec<StoredRecord>,
}

#[derive(PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanos: i64,
}

impl Identity {
    fn read(metadata: &fs::Metadata) -> Result<Self> {
        if !metadata.is_file() || metadata.mode() & 0o077 != 0 {
            return Err(fail("database and lock must be private regular files"));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec(),
        })
    }
}

pub struct Outcome {
    pub status: u16,
    pub body: Vec<u8>,
    pub mutated: bool,
}

impl Outcome {
    fn error(status: u16, message: &'static [u8]) -> Self {
        Self {
            status,
            body: message.to_vec(),
            mutated: false,
        }
    }
}

pub struct Database {
    path: PathBuf,
    parent: PathBuf,
    // An advisory sidecar lock is held for this database lifetime and never unlinked.
    _lock: File,
    profile_id: String,
    revision: u64,
    identity: Option<Identity>,
    records: BTreeMap<String, Vec<u8>>,
}

impl Database {
    pub fn open(path: &Path, profile_id: &str) -> Result<Self> {
        if !path.is_absolute() {
            return Err(fail("database path must be absolute"));
        }
        let parent = path
            .parent()
            .ok_or_else(|| fail("invalid database path"))?
            .canonicalize()?;
        let name = path
            .file_name()
            .ok_or_else(|| fail("invalid database path"))?;
        let path = parent.join(name);
        let mut lock_name = name.to_os_string();
        lock_name.push(".lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(parent.join(lock_name))?;
        Identity::read(&lock.metadata()?)?;
        lock.try_lock()
            .map_err(|_| fail("database is already in use or cannot be locked"))?;
        let mut database = Self {
            path,
            parent,
            _lock: lock,
            profile_id: profile_id.into(),
            revision: 0,
            identity: None,
            records: BTreeMap::new(),
        };
        match fs::symlink_metadata(&database.path) {
            Ok(_) => {
                let mut file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&database.path)?;
                let identity = Identity::read(&file.metadata()?)?;
                if identity.length > MAX_DB as u64 {
                    return Err(fail("database exceeds limit"));
                }
                let mut bytes = Vec::new();
                (&mut file)
                    .take(MAX_DB as u64 + 1)
                    .read_to_end(&mut bytes)?;
                if bytes.len() > MAX_DB {
                    return Err(fail("database exceeds limit"));
                }
                let snapshot: Snapshot = serde_json::from_slice(&bytes)?;
                if snapshot.format != "zkweb-zk-records-v1"
                    || snapshot.profile_id != profile_id
                    || snapshot.records.len() > MAX_RECORDS
                {
                    return Err(fail("database format or profile mismatch"));
                }
                let record_bytes = serde_json::to_vec(&snapshot.records)?;
                if hex::encode(Sha256::digest(&record_bytes)) != snapshot.records_sha256 {
                    return Err(fail("database checksum mismatch"));
                }
                for record in snapshot.records {
                    if !protocol::valid_key(&record.key)
                        || record.value_base64.len() > MAX_BODY.div_ceil(3) * 4
                    {
                        return Err(fail("invalid stored record"));
                    }
                    let body = STANDARD.decode(&record.value_base64)?;
                    if body.len() > MAX_BODY
                        || STANDARD.encode(&body) != record.value_base64
                        || database.records.insert(record.key, body).is_some()
                    {
                        return Err(fail("invalid or duplicate stored record"));
                    }
                }
                database.revision = snapshot.revision;
                database.identity = Some(identity);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                database.write(&BTreeMap::new(), 0)?;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(database)
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn check_current(&self) -> Result<()> {
        if let Some(expected) = &self.identity {
            let metadata = fs::symlink_metadata(&self.path)?;
            if metadata.file_type().is_symlink() || Identity::read(&metadata)? != *expected {
                return Err(fail("database changed outside this listener"));
            }
        } else if self.path.try_exists()? {
            return Err(fail("refusing to overwrite an existing database"));
        }
        Ok(())
    }

    /// The caller must have verified authorization for this exact method/key/body.
    pub fn execute(&mut self, method: &str, key: &str, body: &[u8]) -> Result<Outcome> {
        if !protocol::valid_key(key)
            || body.len() > MAX_BODY
            || !matches!(method, "POST" | "GET" | "PUT" | "DELETE")
            || (matches!(method, "GET" | "DELETE") && !body.is_empty())
        {
            return Err(fail("invalid database operation"));
        }
        self.check_current()?;
        let existing = self.records.get(key);
        if method == "GET" {
            return Ok(match existing {
                Some(value) => Outcome {
                    status: 200,
                    body: value.clone(),
                    mutated: false,
                },
                None => Outcome::error(404, br#"{"error":"record not found"}"#),
            });
        }
        if method == "POST" && existing.is_some() {
            return Ok(Outcome::error(409, br#"{"error":"record exists"}"#));
        }
        if matches!(method, "PUT" | "DELETE") && existing.is_none() {
            return Ok(Outcome::error(404, br#"{"error":"record not found"}"#));
        }
        if method == "POST" && self.records.len() >= MAX_RECORDS {
            return Ok(Outcome::error(507, br#"{"error":"store full"}"#));
        }
        let response_body = if method == "DELETE" {
            existing.ok_or_else(|| fail("missing record"))?.clone()
        } else {
            body.to_vec()
        };
        let mut candidate = self.records.clone();
        if method == "DELETE" {
            candidate.remove(key);
        } else {
            candidate.insert(key.into(), body.to_vec());
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or_else(|| fail("database revision exhausted"))?;
        self.write(&candidate, revision)?;
        self.records = candidate;
        self.revision = revision;
        Ok(Outcome {
            status: if method == "POST" { 201 } else { 200 },
            body: response_body,
            mutated: true,
        })
    }

    fn write(&mut self, records: &BTreeMap<String, Vec<u8>>, revision: u64) -> Result<()> {
        self.check_current()?;
        if records.len() > MAX_RECORDS {
            return Err(fail("database capacity exceeded"));
        }
        let records = records
            .iter()
            .map(|(key, body)| StoredRecord {
                key: key.clone(),
                value_base64: STANDARD.encode(body),
            })
            .collect::<Vec<_>>();
        let checksum = hex::encode(Sha256::digest(serde_json::to_vec(&records)?));
        let bytes = serde_json::to_vec(&Snapshot {
            format: "zkweb-zk-records-v1".into(),
            profile_id: self.profile_id.clone(),
            revision,
            records_sha256: checksum,
            records,
        })?;
        if bytes.len() > MAX_DB {
            return Err(fail("database exceeds limit"));
        }
        let temporary = self
            .parent
            .join(format!(".zkweb-records-{}.tmp", protocol::random_id()));
        let result = (|| -> Result<Identity> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            self.check_current()?;
            if self.identity.is_some() {
                fs::rename(&temporary, &self.path)?;
            } else {
                fs::hard_link(&temporary, &self.path)?;
                fs::remove_file(&temporary)?;
            }
            File::open(&self.parent)?.sync_all()?;
            Identity::read(&file.metadata()?)
        })();
        let _ = fs::remove_file(&temporary);
        self.identity = Some(result?);
        Ok(())
    }
}
