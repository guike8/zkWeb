// SPDX-License-Identifier: AGPL-3.0-or-later
//! Trusted offline provisioning with separate server and member material.
use crate::{PROTOCOL, Result, crypto, fail};
use ark_bn254::Bn254;
use ark_groth16::{ProvingKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub const MAX_PROVING_KEY: usize = 32 * 1024 * 1024;
pub const MAX_VERIFYING_KEY: usize = 1024 * 1024;
const MAX_METADATA: usize = 16 * 1024;
const PROVING_KEY: &str = "proving-key.g16";
const VERIFYING_KEY: &str = "verifying-key.g16";
const CREDENTIAL: &str = "credential.json";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub role: String,
    pub protocol: String,
    pub parameters: String,
    pub profile_id: String,
    pub group_root: String,
    pub members: usize,
    pub proving_key_sha256: String,
    pub verifying_key_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_sha256: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialFile {
    format: String,
    secret: String,
    siblings: Vec<String>,
    index: u8,
}

pub struct ClientProfile {
    pub manifest: Manifest,
    pub proving_key: ProvingKey<Bn254>,
    pub credential: crypto::Credential,
}
pub struct ServerProfile {
    pub manifest: Manifest,
    pub verifying_key: VerifyingKey<Bn254>,
}

#[derive(Serialize)]
pub struct SetupResult {
    pub format: &'static str,
    pub server_dir: PathBuf,
    pub client_dirs: Vec<PathBuf>,
    pub profile_id: String,
    pub protocol: &'static str,
    pub members: usize,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn canonical_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn profile_id(manifest: &Manifest) -> String {
    let mut context = b"zkweb-zk-authorization-profile-v1\0".to_vec();
    for field in [
        PROTOCOL,
        crypto::PARAMETERS,
        manifest.group_root.as_str(),
        manifest.proving_key_sha256.as_str(),
        manifest.verifying_key_sha256.as_str(),
    ] {
        context.extend_from_slice(&(field.len() as u32).to_be_bytes());
        context.extend_from_slice(field.as_bytes());
    }
    context.extend_from_slice(&(manifest.members as u64).to_be_bytes());
    digest(&context)
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
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize, private: bool) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err(fail("profile object must be a bounded regular file"));
    }
    if private && metadata.mode() & 0o077 != 0 {
        return Err(fail(
            "credential file permissions must exclude group and other access",
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(fail("profile object exceeds its size limit"));
    }
    Ok(bytes)
}

fn pinned(path: &Path, expected: &str, maximum: usize, private: bool) -> Result<Vec<u8>> {
    if !canonical_digest(expected) {
        return Err(fail("invalid profile object hash"));
    }
    let bytes = read_bounded(path, maximum, private)?;
    if digest(&bytes) != expected {
        return Err(fail("profile object hash mismatch"));
    }
    Ok(bytes)
}

/// The provisioner is trusted and temporarily knows every member secret and
/// Groth16 setup randomness. This is not a multiparty production ceremony.
pub fn setup(output: &Path, members: usize) -> Result<SetupResult> {
    if !(1..=crypto::MAX_MEMBERS).contains(&members) {
        return Err(fail("member count must be between 1 and 16"));
    }
    directory(output)?;
    let server_dir = output.join("server");
    directory(&server_dir)?;
    let mut client_dirs = Vec::with_capacity(members);
    for index in 0..members {
        let path = output.join(format!("client-{index}"));
        directory(&path)?;
        client_dirs.push(path);
    }
    let material = crypto::generate_setup(members)?;
    let pk = crypto::serialize(&material.proving_key, MAX_PROVING_KEY)?;
    let vk = crypto::serialize(&material.verifying_key, MAX_VERIFYING_KEY)?;
    let mut manifest = Manifest {
        format: "zkweb-zk-profile-v1".into(),
        role: "server".into(),
        protocol: PROTOCOL.into(),
        parameters: crypto::PARAMETERS.into(),
        profile_id: String::new(),
        group_root: crypto::field_hex(&material.group_root),
        members,
        proving_key_sha256: digest(&pk),
        verifying_key_sha256: digest(&vk),
        credential_sha256: None,
    };
    manifest.profile_id = profile_id(&manifest);
    write_new(&server_dir.join(VERIFYING_KEY), &vk)?;
    write_new(
        &server_dir.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    for (path, credential) in client_dirs.iter().zip(material.credentials) {
        let credential = CredentialFile {
            format: "zkweb-zk-credential-v1".into(),
            secret: crypto::field_hex(&credential.secret),
            siblings: credential.siblings.iter().map(crypto::field_hex).collect(),
            index: credential.index,
        };
        let bytes = serde_json::to_vec_pretty(&credential)?;
        let mut client_manifest = manifest.clone();
        client_manifest.role = "client".into();
        client_manifest.credential_sha256 = Some(digest(&bytes));
        write_new(&path.join(PROVING_KEY), &pk)?;
        write_new(&path.join(CREDENTIAL), &bytes)?;
        write_new(
            &path.join("manifest.json"),
            &serde_json::to_vec_pretty(&client_manifest)?,
        )?;
    }
    Ok(SetupResult {
        format: "zkweb-zk-setup-v1",
        server_dir: fs::canonicalize(server_dir)?,
        client_dirs: client_dirs
            .into_iter()
            .map(fs::canonicalize)
            .collect::<std::io::Result<_>>()?,
        profile_id: manifest.profile_id,
        protocol: PROTOCOL,
        members,
    })
}

fn manifest(directory: &Path, role: &str) -> Result<Manifest> {
    let manifest: Manifest = serde_json::from_slice(&read_bounded(
        &directory.join("manifest.json"),
        MAX_METADATA,
        false,
    )?)?;
    if manifest.format != "zkweb-zk-profile-v1"
        || manifest.role != role
        || manifest.protocol != PROTOCOL
        || manifest.parameters != crypto::PARAMETERS
        || !(1..=crypto::MAX_MEMBERS).contains(&manifest.members)
        || !canonical_digest(&manifest.proving_key_sha256)
        || !canonical_digest(&manifest.verifying_key_sha256)
        || manifest.profile_id != profile_id(&manifest)
    {
        return Err(fail("unsupported or corrupt authorization profile"));
    }
    crypto::parse_field(&manifest.group_root)?;
    Ok(manifest)
}

pub fn load_server(directory: &Path) -> Result<ServerProfile> {
    let manifest = manifest(directory, "server")?;
    if manifest.credential_sha256.is_some()
        || directory.join(CREDENTIAL).exists()
        || directory.join(PROVING_KEY).exists()
    {
        return Err(fail(
            "listener profile must contain only verification material",
        ));
    }
    let verifying_key = crypto::deserialize(
        &pinned(
            &directory.join(VERIFYING_KEY),
            &manifest.verifying_key_sha256,
            MAX_VERIFYING_KEY,
            false,
        )?,
        MAX_VERIFYING_KEY,
    )?;
    crypto::validate_verifying_key(&verifying_key)?;
    Ok(ServerProfile {
        manifest,
        verifying_key,
    })
}

pub fn load_client(directory: &Path) -> Result<ClientProfile> {
    let manifest = manifest(directory, "client")?;
    let expected = manifest
        .credential_sha256
        .as_ref()
        .ok_or_else(|| fail("member profile is missing its credential hash"))?;
    let credential: CredentialFile = serde_json::from_slice(&pinned(
        &directory.join(CREDENTIAL),
        expected,
        MAX_METADATA,
        true,
    )?)?;
    if credential.format != "zkweb-zk-credential-v1"
        || credential.siblings.len() != crypto::DEPTH
        || credential.index as usize >= manifest.members
    {
        return Err(fail("invalid member credential schema"));
    }
    let siblings = credential
        .siblings
        .iter()
        .map(|s| crypto::parse_field(s))
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| fail("invalid member path"))?;
    let credential = crypto::Credential {
        secret: crypto::parse_field(&credential.secret)?,
        siblings,
        index: credential.index,
    };
    if crypto::field_hex(&crypto::credential_root(&credential)?) != manifest.group_root {
        return Err(fail(
            "credential does not belong to the authorization profile",
        ));
    }
    let proving_key: ProvingKey<Bn254> = crypto::deserialize(
        &pinned(
            &directory.join(PROVING_KEY),
            &manifest.proving_key_sha256,
            MAX_PROVING_KEY,
            false,
        )?,
        MAX_PROVING_KEY,
    )?;
    crypto::validate_verifying_key(&proving_key.vk)?;
    if digest(&crypto::serialize(&proving_key.vk, MAX_VERIFYING_KEY)?)
        != manifest.verifying_key_sha256
    {
        return Err(fail(
            "proving key does not match the registered verifying key",
        ));
    }
    Ok(ClientProfile {
        manifest,
        proving_key,
        credential,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_never_reuses_existing_output() -> Result<()> {
        let output = tempfile::tempdir()?;
        let sentinel = output.path().join("sentinel");
        fs::write(&sentinel, b"preserve existing data")?;
        assert!(setup(output.path(), 1).is_err());
        assert_eq!(fs::read(sentinel)?, b"preserve existing data");
        assert_eq!(fs::read_dir(output.path())?.count(), 1);
        Ok(())
    }
}
