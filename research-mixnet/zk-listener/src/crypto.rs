// SPDX-License-Identifier: AGPL-3.0-or-later
//! A distinct Groth16 membership-and-request-authorization circuit.
//!
//! The Poseidon construction and native/R1CS pairing follow the existing
//! `protocol/rust/crates/zkapi-proof/src/groth16.rs` helpers. This circuit does
//! not import the wallet's note, payment, balance, or state-signature rules.
use crate::{Result, fail};
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::{
    PoseidonConfig, PoseidonSponge, find_poseidon_ark_and_mds,
};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey, prepare_verifying_key};
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, convert::ToBitsGadget, eq::EqGadget, fields::fp::FpVar,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use rand::rngs::OsRng;
use std::sync::OnceLock;

pub const DEPTH: usize = 4;
pub const MAX_MEMBERS: usize = 1 << DEPTH;
pub const PUBLIC_INPUTS: usize = 4;
pub const PROOF_BYTES: usize = 128;
pub const PARAMETERS: &str = "bn254-groth16-v1;poseidon-rate2-capacity1-alpha5-full8-partial57;merkle-depth4;sha256-two-be128-limbs;zkweb-auth-domains-v1;private-randomized-tag-v1";

const DOMAIN_IDENTITY: &[u8] = b"zkweb.zk.identity.v1";
const DOMAIN_NODE: &[u8] = b"zkweb.zk.node.v1";
const DOMAIN_AUTHORIZATION: &[u8] = b"zkweb.zk.authorization.v1";

#[derive(Clone)]
pub struct Credential {
    pub secret: Fr,
    pub siblings: [Fr; DEPTH],
    pub index: u8,
}

pub struct SetupMaterial {
    pub proving_key: ProvingKey<Bn254>,
    pub verifying_key: VerifyingKey<Bn254>,
    pub group_root: Fr,
    pub credentials: Vec<Credential>,
}

pub struct Authorization {
    pub proof: Vec<u8>,
    pub tag: String,
}

fn poseidon_config() -> &'static PoseidonConfig<Fr> {
    static CONFIG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(Fr::MODULUS_BIT_SIZE as u64, 2, 8, 57, 0);
        PoseidonConfig::new(8, 57, 5, mds, ark, 2, 1)
    })
}

fn domain(label: &[u8]) -> Fr {
    // All fixed domain labels are shorter than 31 bytes and therefore below Fr.
    Fr::from_be_bytes_mod_order(label)
}

fn hash(inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::new(poseidon_config());
    sponge.absorb(&inputs);
    sponge.squeeze_native_field_elements(1)[0]
}

fn hash_var(
    cs: ConstraintSystemRef<Fr>,
    inputs: &[FpVar<Fr>],
) -> std::result::Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs, poseidon_config());
    sponge.absorb(&inputs)?;
    Ok(sponge.squeeze_field_elements(1)?[0].clone())
}

fn identity(secret: Fr) -> Fr {
    hash(&[domain(DOMAIN_IDENTITY), secret])
}

fn node(left: Fr, right: Fr) -> Fr {
    // Domain in the capacity lane distinguishes nodes from sponge hashes.
    let mut sponge = PoseidonSponge::new(poseidon_config());
    sponge.state[0] = domain(DOMAIN_NODE);
    sponge.absorb(&[left, right].as_slice());
    sponge.squeeze_native_field_elements(1)[0]
}

fn node_var(
    cs: ConstraintSystemRef<Fr>,
    left: FpVar<Fr>,
    right: FpVar<Fr>,
) -> std::result::Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs, poseidon_config());
    sponge.state[0] = FpVar::Constant(domain(DOMAIN_NODE));
    sponge.absorb(&[left, right].as_slice())?;
    Ok(sponge.squeeze_field_elements(1)?[0].clone())
}

/// Preserve the entire SHA-256 digest; each half is strictly smaller than Fr.
pub fn digest_limbs(digest: &[u8; 32]) -> [Fr; 2] {
    [
        Fr::from_be_bytes_mod_order(&digest[..16]),
        Fr::from_be_bytes_mod_order(&digest[16..]),
    ]
}

fn authorization_tag(secret: Fr, limbs: [Fr; 2], blinding: Fr) -> Fr {
    hash(&[
        domain(DOMAIN_AUTHORIZATION),
        secret,
        limbs[0],
        limbs[1],
        blinding,
    ])
}

pub fn credential_root(credential: &Credential) -> Result<Fr> {
    if credential.index as usize >= MAX_MEMBERS || credential.secret == Fr::from(0u64) {
        return Err(fail("invalid authorization credential"));
    }
    let mut current = identity(credential.secret);
    for (level, sibling) in credential.siblings.iter().enumerate() {
        current = if (credential.index >> level) & 1 == 0 {
            node(current, *sibling)
        } else {
            node(*sibling, current)
        };
    }
    Ok(current)
}

#[derive(Clone)]
struct AuthorizationCircuit {
    group_root: Fr,
    digest: [Fr; 2],
    tag: Fr,
    credential: Credential,
    tag_blinding: Fr,
}

impl ConstraintSynthesizer<Fr> for AuthorizationCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> std::result::Result<(), SynthesisError> {
        // This allocation order is the public verification interface.
        let root = FpVar::new_input(cs.clone(), || Ok(self.group_root))?;
        let digest0 = FpVar::new_input(cs.clone(), || Ok(self.digest[0]))?;
        let digest1 = FpVar::new_input(cs.clone(), || Ok(self.digest[1]))?;
        let tag = FpVar::new_input(cs.clone(), || Ok(self.tag))?;
        for limb in [&digest0, &digest1] {
            for bit in limb.to_bits_le()?.iter().skip(128) {
                bit.enforce_equal(&Boolean::FALSE)?;
            }
        }
        let secret = FpVar::new_witness(cs.clone(), || Ok(self.credential.secret))?;
        let blinding = FpVar::new_witness(cs.clone(), || Ok(self.tag_blinding))?;
        secret.enforce_not_equal(&FpVar::Constant(Fr::from(0u64)))?;
        let mut current = hash_var(
            cs.clone(),
            &[FpVar::Constant(domain(DOMAIN_IDENTITY)), secret.clone()],
        )?;
        for level in 0..DEPTH {
            let bit =
                Boolean::new_witness(cs.clone(), || Ok((self.credential.index >> level) & 1 != 0))?;
            let sibling = FpVar::new_witness(cs.clone(), || Ok(self.credential.siblings[level]))?;
            let left = bit.select(&sibling, &current)?;
            let right = bit.select(&current, &sibling)?;
            current = node_var(cs.clone(), left, right)?;
        }
        current.enforce_equal(&root)?;
        // Merely allocating the digest as a public input would not bind it.
        // Both 128-bit limbs participate in this constrained secret-dependent tag.
        hash_var(
            cs,
            &[
                FpVar::Constant(domain(DOMAIN_AUTHORIZATION)),
                secret,
                digest0,
                digest1,
                blinding,
            ],
        )?
        .enforce_equal(&tag)
    }
}

fn credentials(members: usize) -> Result<(Fr, Vec<Credential>)> {
    if !(1..=MAX_MEMBERS).contains(&members) {
        return Err(fail("member count must be between 1 and 16"));
    }
    let mut rng = OsRng;
    let mut secrets = Vec::with_capacity(members);
    while secrets.len() < members {
        let secret = Fr::rand(&mut rng);
        if secret != Fr::from(0u64) && !secrets.contains(&secret) {
            secrets.push(secret);
        }
    }
    let mut leaves = vec![Fr::from(0u64); MAX_MEMBERS];
    for (leaf, secret) in leaves.iter_mut().zip(&secrets) {
        *leaf = identity(*secret);
    }
    let mut levels = vec![leaves];
    for level in 0..DEPTH {
        levels.push(
            levels[level]
                .chunks_exact(2)
                .map(|pair| node(pair[0], pair[1]))
                .collect(),
        );
    }
    let root = levels[DEPTH][0];
    let credentials = secrets
        .into_iter()
        .enumerate()
        .map(|(index, secret)| Credential {
            secret,
            index: index as u8,
            siblings: std::array::from_fn(|level| levels[level][(index >> level) ^ 1]),
        })
        .collect();
    Ok((root, credentials))
}

/// Trusted offline single-party setup. Never substitute published test keys.
pub fn generate_setup(members: usize) -> Result<SetupMaterial> {
    let (root, credentials) = credentials(members)?;
    let digest = digest_limbs(&[0u8; 32]);
    let tag_blinding = Fr::from(1u64);
    let circuit = AuthorizationCircuit {
        group_root: root,
        digest,
        tag: authorization_tag(credentials[0].secret, digest, tag_blinding),
        credential: credentials[0].clone(),
        tag_blinding,
    };
    let proving_key =
        Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut OsRng)?;
    let verifying_key = proving_key.vk.clone();
    validate_verifying_key(&verifying_key)?;
    Ok(SetupMaterial {
        proving_key,
        verifying_key,
        group_root: root,
        credentials,
    })
}

pub fn validate_verifying_key(key: &VerifyingKey<Bn254>) -> Result<()> {
    if key.gamma_abc_g1.len() != PUBLIC_INPUTS + 1 {
        return Err(fail(
            "verifying key does not match the authorization circuit",
        ));
    }
    Ok(())
}

pub fn prove(
    proving_key: &ProvingKey<Bn254>,
    credential: &Credential,
    group_root: &str,
    digest: &[u8; 32],
) -> Result<Authorization> {
    validate_verifying_key(&proving_key.vk)?;
    let root = parse_field(group_root)?;
    if credential_root(credential)? != root {
        return Err(fail(
            "credential is not a member of the configured authorization group",
        ));
    }
    let digest = digest_limbs(digest);
    // A fresh private tag witness prevents an adversarial listener from making
    // repeated challenges expose a stable credential-specific public tag.
    let tag_blinding = Fr::rand(&mut OsRng);
    let tag = authorization_tag(credential.secret, digest, tag_blinding);
    let circuit = AuthorizationCircuit {
        group_root: root,
        digest,
        tag,
        credential: credential.clone(),
        tag_blinding,
    };
    // The randomized prover is required: the *_no_zk constructor is never used.
    let proof =
        Groth16::<Bn254>::create_random_proof_with_reduction(circuit, proving_key, &mut OsRng)?;
    let proof = serialize(&proof, PROOF_BYTES)?;
    if proof.len() != PROOF_BYTES {
        return Err(fail("unexpected authorization proof size"));
    }
    Ok(Authorization {
        proof,
        tag: field_hex(&tag),
    })
}

pub fn verify(
    verifying_key: &VerifyingKey<Bn254>,
    group_root: &str,
    digest: &[u8; 32],
    proof: &[u8],
    tag: &str,
) -> Result<bool> {
    validate_verifying_key(verifying_key)?;
    if proof.len() != PROOF_BYTES {
        return Err(fail("authorization proof must contain exactly 128 bytes"));
    }
    let proof: Proof<Bn254> = deserialize(proof, PROOF_BYTES)?;
    let root = parse_field(group_root)?;
    let tag = parse_field(tag)?;
    let digest = digest_limbs(digest);
    Ok(Groth16::<Bn254>::verify_proof(
        &prepare_verifying_key(verifying_key),
        &proof,
        &[root, digest[0], digest[1], tag],
    )?)
}

/// Canonical 32-byte big-endian Fr, encoded as exactly 64 lower-case hex digits.
pub fn field_hex(value: &Fr) -> String {
    let raw = value.into_bigint().to_bytes_be();
    let mut bytes = [0u8; 32];
    bytes[32 - raw.len()..].copy_from_slice(&raw);
    hex::encode(bytes)
}

pub fn parse_field(encoded: &str) -> Result<Fr> {
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(fail("invalid canonical field encoding"));
    }
    let bytes = hex::decode(encoded)?;
    let value = Fr::from_be_bytes_mod_order(&bytes);
    if field_hex(&value) != encoded {
        return Err(fail("field encoding is out of range"));
    }
    Ok(value)
}

pub fn serialize<T: CanonicalSerialize>(value: &T, maximum: usize) -> Result<Vec<u8>> {
    let size = value.serialized_size(Compress::Yes);
    if size > maximum {
        return Err(fail("cryptographic object exceeds its size limit"));
    }
    let mut bytes = Vec::with_capacity(size);
    value.serialize_with_mode(&mut bytes, Compress::Yes)?;
    Ok(bytes)
}

pub fn deserialize<T: CanonicalDeserialize>(bytes: &[u8], maximum: usize) -> Result<T> {
    if bytes.len() > maximum {
        return Err(fail("cryptographic object exceeds its size limit"));
    }
    let mut remaining = bytes;
    let value = T::deserialize_with_mode(&mut remaining, Compress::Yes, Validate::Yes)?;
    if !remaining.is_empty() {
        return Err(fail("trailing bytes in cryptographic object"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    use ark_relations::r1cs::ConstraintSystem;

    fn satisfied(circuit: AuthorizationCircuit) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).is_ok() && cs.is_satisfied().unwrap()
    }

    #[test]
    fn membership_and_every_public_input_are_constrained() {
        let (root, credentials) = credentials(4).unwrap();
        for credential in &credentials {
            let digest = digest_limbs(&[42; 32]);
            let tag_blinding = Fr::from(11u64);
            let circuit = AuthorizationCircuit {
                group_root: root,
                digest,
                tag: authorization_tag(credential.secret, digest, tag_blinding),
                credential: credential.clone(),
                tag_blinding,
            };
            assert!(satisfied(circuit.clone()));
            let mut changed = circuit.clone();
            changed.group_root += Fr::from(1u64);
            assert!(!satisfied(changed));
            let mut changed = circuit.clone();
            changed.digest[0] += Fr::from(1u64);
            assert!(!satisfied(changed));
            let mut changed = circuit.clone();
            changed.digest[1] += Fr::from(1u64);
            assert!(!satisfied(changed));
            let mut changed = circuit.clone();
            changed.tag += Fr::from(1u64);
            assert!(!satisfied(changed));
            let mut changed = circuit.clone();
            changed.credential.siblings[0] += Fr::from(1u64);
            assert!(!satisfied(changed));
            let mut changed = circuit.clone();
            changed.credential.index ^= 1;
            assert!(!satisfied(changed));
            let mut changed = circuit.clone();
            changed.credential.secret += Fr::from(1u64);
            assert!(!satisfied(changed));
            let mut changed = circuit.clone();
            changed.digest[0] = Fr::from(2u64).pow([128]);
            changed.tag = authorization_tag(
                changed.credential.secret,
                changed.digest,
                changed.tag_blinding,
            );
            assert!(!satisfied(changed));
        }
    }

    #[test]
    fn canonical_field_encoding_preserves_both_digest_halves() {
        assert_eq!(
            parse_field(&field_hex(&Fr::from(0u64))).unwrap(),
            Fr::from(0u64)
        );
        assert!(parse_field(&"f".repeat(64)).is_err());
        assert!(parse_field(&"F".repeat(64)).is_err());
        assert!(parse_field("00").is_err());
        let limbs = digest_limbs(&[255u8; 32]);
        assert_eq!(
            field_hex(&limbs[0]),
            format!("{}{}", "0".repeat(32), "f".repeat(32))
        );
        assert_eq!(limbs[0], limbs[1]);
    }

    #[test]
    fn nonzero_secret_is_required_even_with_a_matching_root_and_tag() {
        let (_, mut members) = credentials(1).unwrap();
        let mut credential = members.remove(0);
        credential.secret = Fr::from(0u64);
        let mut root = identity(credential.secret);
        for (level, sibling) in credential.siblings.iter().enumerate() {
            root = if (credential.index >> level) & 1 == 0 {
                node(root, *sibling)
            } else {
                node(*sibling, root)
            };
        }
        let digest = digest_limbs(&[17u8; 32]);
        let tag_blinding = Fr::from(9u64);
        let circuit = AuthorizationCircuit {
            group_root: root,
            digest,
            tag: authorization_tag(credential.secret, digest, tag_blinding),
            credential,
            tag_blinding,
        };
        assert!(!satisfied(circuit));
    }

    #[test]
    fn repeated_context_gets_fresh_tags_and_both_proofs_verify() {
        let material = generate_setup(2).unwrap();
        let root = field_hex(&material.group_root);
        let digest = [73u8; 32];
        let first = prove(
            &material.proving_key,
            &material.credentials[0],
            &root,
            &digest,
        )
        .unwrap();
        let second = prove(
            &material.proving_key,
            &material.credentials[0],
            &root,
            &digest,
        )
        .unwrap();
        assert_ne!(first.tag, second.tag);
        assert_ne!(first.proof, second.proof);
        assert!(
            verify(
                &material.verifying_key,
                &root,
                &digest,
                &first.proof,
                &first.tag
            )
            .unwrap()
        );
        assert!(
            verify(
                &material.verifying_key,
                &root,
                &digest,
                &second.proof,
                &second.tag
            )
            .unwrap()
        );
        let mut changed_digest = digest;
        changed_digest[0] ^= 1;
        assert!(
            !verify(
                &material.verifying_key,
                &root,
                &changed_digest,
                &first.proof,
                &first.tag
            )
            .unwrap()
        );
        let changed_tag = field_hex(&(parse_field(&first.tag).unwrap() + Fr::from(1u64)));
        assert!(
            !verify(
                &material.verifying_key,
                &root,
                &digest,
                &first.proof,
                &changed_tag
            )
            .unwrap()
        );
    }
}
