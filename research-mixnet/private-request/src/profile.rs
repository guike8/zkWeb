// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{MAX_CRS, MAX_KEY, PROTOCOL, Result, TFHE_VERSION, crypto, fail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use tfhe::zk::CompactPkeCrs;
use tfhe::{ClientKey, CompactPublicKey, ServerKey};

const CLIENT: &str = "client-key.tfhe";
const SERVER: &str = "server-key.tfhe";
const CPK: &str = "compact-public-key.tfhe";
const CRS: &str = "crs.tfhe";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub role: String,
    pub protocol: String,
    pub tfhe_version: String,
    pub parameters: String,
    pub profile_id: String,
    pub crs_sha256: String,
    pub compact_public_key_sha256: String,
    pub server_key_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_key_sha256: Option<String>,
}

pub struct PublicProfile {
    pub manifest: Manifest,
    pub crs: CompactPkeCrs,
    pub public_key: CompactPublicKey,
}
pub struct ClientProfile {
    pub public: PublicProfile,
    pub client_key: ClientKey,
}
pub struct ServerProfile {
    pub public: PublicProfile,
    pub server_key: ServerKey,
}

#[derive(Serialize)]
pub struct SetupResult {
    pub format: &'static str,
    pub client_dir: PathBuf,
    pub server_dir: PathBuf,
    pub profile_id: String,
    pub protocol: &'static str,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn profile_id(manifest: &Manifest) -> String {
    digest(
        format!(
            "zkweb-private-profile-v1\0{}\0{}\0{}\0{}\0{}\0{}",
            PROTOCOL,
            TFHE_VERSION,
            crypto::PARAMETERS,
            manifest.crs_sha256,
            manifest.compact_public_key_sha256,
            manifest.server_key_sha256
        )
        .as_bytes(),
    )
}
fn directory(path: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(fail("profile file must be a regular file"));
    }
    let mut file = File::open(path)?;
    if file.metadata()?.len() > maximum as u64 {
        return Err(fail("profile file exceeds limit"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(fail("profile file exceeds limit"));
    }
    Ok(bytes)
}
fn pinned(path: &Path, expected: &str, maximum: usize) -> Result<Vec<u8>> {
    let bytes = read_bounded(path, maximum)?;
    if digest(&bytes) != expected {
        return Err(fail("profile file hash mismatch"));
    }
    Ok(bytes)
}

/// Run only on a trusted offline provisioner. The secret key is never copied to server_dir.
pub fn setup(output: &Path) -> Result<SetupResult> {
    // Reserve all directories before expensive work; a preexisting path is always an error.
    directory(output)?;
    let client_dir = output.join("client");
    let server_dir = output.join("server");
    directory(&client_dir)?;
    directory(&server_dir)?;
    let config = crypto::config();
    let crs = CompactPkeCrs::from_config(config, 2)?;
    let client_key = ClientKey::generate(config);
    let public_key = CompactPublicKey::try_new(&client_key)?;
    let server_key = ServerKey::new(&client_key);
    let crs_bytes = crypto::serialize(&crs, MAX_CRS)?;
    let pk_bytes = crypto::serialize(&public_key, MAX_KEY)?;
    let sk_bytes = crypto::serialize(&server_key, MAX_KEY)?;
    let ck_bytes = crypto::serialize(&client_key, MAX_KEY)?;
    let mut manifest = Manifest {
        format: "zkweb-private-profile-v1".into(),
        role: "client".into(),
        protocol: PROTOCOL.into(),
        tfhe_version: TFHE_VERSION.into(),
        parameters: crypto::PARAMETERS.into(),
        profile_id: String::new(),
        crs_sha256: digest(&crs_bytes),
        compact_public_key_sha256: digest(&pk_bytes),
        server_key_sha256: digest(&sk_bytes),
        client_key_sha256: Some(digest(&ck_bytes)),
    };
    manifest.profile_id = profile_id(&manifest);
    for dir in [&client_dir, &server_dir] {
        write_new(&dir.join(CRS), &crs_bytes)?;
        write_new(&dir.join(CPK), &pk_bytes)?;
    }
    write_new(&client_dir.join(CLIENT), &ck_bytes)?;
    write_new(&server_dir.join(SERVER), &sk_bytes)?;
    write_new(
        &client_dir.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    manifest.role = "server".into();
    manifest.client_key_sha256 = None;
    write_new(
        &server_dir.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(SetupResult {
        format: "zkweb-private-setup-v1",
        client_dir: fs::canonicalize(client_dir)?,
        server_dir: fs::canonicalize(server_dir)?,
        profile_id: manifest.profile_id,
        protocol: PROTOCOL,
    })
}

fn public(dir: &Path, role: &str) -> Result<PublicProfile> {
    let manifest: Manifest =
        serde_json::from_slice(&read_bounded(&dir.join("manifest.json"), 16 * 1024)?)?;
    if manifest.format != "zkweb-private-profile-v1"
        || manifest.protocol != PROTOCOL
        || manifest.role != role
        || manifest.tfhe_version != TFHE_VERSION
        || manifest.parameters != crypto::PARAMETERS
        || manifest.profile_id != profile_id(&manifest)
    {
        return Err(fail("unsupported or corrupt profile manifest"));
    }
    if role == "server" && (manifest.client_key_sha256.is_some() || dir.join(CLIENT).exists()) {
        return Err(fail("server profile must not contain a client secret key"));
    }
    let crs = crypto::deserialize_trusted(
        &pinned(&dir.join(CRS), &manifest.crs_sha256, MAX_CRS)?,
        MAX_CRS,
    )?;
    let public_key = crypto::deserialize_trusted(
        &pinned(&dir.join(CPK), &manifest.compact_public_key_sha256, MAX_KEY)?,
        MAX_KEY,
    )?;
    Ok(PublicProfile {
        manifest,
        crs,
        public_key,
    })
}
pub fn load_client(dir: &Path) -> Result<ClientProfile> {
    let public = public(dir, "client")?;
    let expected = public
        .manifest
        .client_key_sha256
        .as_ref()
        .ok_or_else(|| fail("client profile missing secret key hash"))?;
    let client_key =
        crypto::deserialize_trusted(&pinned(&dir.join(CLIENT), expected, MAX_KEY)?, MAX_KEY)?;
    Ok(ClientProfile { public, client_key })
}
pub fn load_server(dir: &Path) -> Result<ServerProfile> {
    let public = public(dir, "server")?;
    let server_key = crypto::deserialize_trusted(
        &pinned(
            &dir.join(SERVER),
            &public.manifest.server_key_sha256,
            MAX_KEY,
        )?,
        MAX_KEY,
    )?;
    Ok(ServerProfile { public, server_key })
}
