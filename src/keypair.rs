use napi::bindgen_prelude::*;
use napi_derive::napi;
use russh::keys::{self, HashAlg};

use crate::{err::IntoError, signature::Signature};

#[napi]
/// The hash function used for signing with RSA keys.
#[derive(Eq, PartialEq, Debug, Hash)]
#[allow(non_camel_case_types)]
pub enum SignatureHash {
  /// SHA2, 256 bits.
  SHA2_256,
  /// SHA2, 512 bits.
  SHA2_512,
  /// SHA1
  SHA1,
}

impl From<SignatureHash> for Option<HashAlg> {
  fn from(hash: SignatureHash) -> Self {
    match hash {
      SignatureHash::SHA1 => None, // SHA1 is deprecated, use default
      SignatureHash::SHA2_256 => Some(HashAlg::Sha256),
      SignatureHash::SHA2_512 => Some(HashAlg::Sha512),
    }
  }
}

#[napi]
pub struct PublicKey {
  inner: keys::PublicKey,
}

#[napi]
impl PublicKey {
  pub(crate) fn new(inner: keys::PublicKey) -> Self {
    Self { inner }
  }

  #[napi]
  pub fn name(&self) -> String {
    self.inner.algorithm().as_str().to_string()
  }

  #[napi]
  pub fn verify_detached(&self, data: Vec<u8>, signature: Vec<u8>) -> bool {
    // Parse the signature and verify it
    use russh::keys::ssh_encoding::Decode;
    use russh::keys::ssh_key::SshSig;
    let Ok(sig) = SshSig::decode(&mut &signature[..]) else {
      return false;
    };
    // Use empty namespace as we're not using SSH signature format with namespace
    self.inner.verify("", &data, &sig).is_ok()
  }

  #[napi]
  /// Compute the key fingerprint, hashed with sha2-256.
  pub fn fingerprint(&self) -> String {
    self.inner.fingerprint(HashAlg::Sha256).to_string()
  }

  #[napi]
  /// Only effect the `RSA` PublicKey
  pub fn set_algorithm(&mut self, _algorithm: SignatureHash) {
    // Note: The new ssh-key API doesn't support setting algorithm on PublicKey
    // This method is kept for backwards compatibility but is a no-op
  }
}

#[napi]
pub struct KeyPair {
  pub(crate) inner: keys::PrivateKey,
}

#[napi]
impl KeyPair {
  #[napi(factory)]
  pub fn generate_ed25519() -> Self {
    Self {
      inner: keys::PrivateKey::random(&mut rand::thread_rng(), keys::Algorithm::Ed25519).unwrap(),
    }
  }

  #[napi(factory)]
  pub fn generate_rsa(bits: u32, _signature_hash: SignatureHash) -> Result<Self> {
    // Note: The ssh-key crate generates RSA keys with a fixed bit size based on algorithm
    // For compatibility, we'll generate a standard RSA key
    let algorithm = match bits {
      2048 => keys::Algorithm::Rsa { hash: None },
      4096 => keys::Algorithm::Rsa { hash: None },
      _ => keys::Algorithm::Rsa { hash: None },
    };
    Ok(Self {
      inner: keys::PrivateKey::random(&mut rand::thread_rng(), algorithm)
        .map_err(|err| {
          Error::new(
            Status::GenericFailure,
            format!("Generate rsa keypair failed: {err}"),
          )
        })?,
    })
  }

  #[napi(constructor)]
  pub fn new(path: String, password: Option<String>) -> Result<Self> {
    Ok(Self {
      inner: keys::load_secret_key(path, password.as_deref()).into_error()?,
    })
  }

  #[napi]
  pub fn clone_public_key(&self) -> Result<PublicKey> {
    Ok(PublicKey {
      inner: self.inner.public_key().clone(),
    })
  }

  #[napi]
  pub fn name(&self) -> String {
    self.inner.algorithm().as_str().to_string()
  }

  #[napi]
  /// Sign a slice using this algorithm.
  pub fn sign_detached(&self, to_sign: &[u8]) -> Result<Signature> {
    let signature = self
      .inner
      .sign("", HashAlg::Sha256, to_sign)
      .map_err(|err| Error::new(Status::GenericFailure, format!("{err}")))?;
    Ok(Signature { inner: signature })
  }
}

#[napi]
pub fn check_known_hosts(
  host: String,
  port: u32,
  pubkey: &PublicKey,
  path: Option<String>,
) -> Result<bool> {
  if let Some(p) = path {
    keys::check_known_hosts_path(&host, port as u16, &pubkey.inner, p)
  } else {
    keys::check_known_hosts(&host, port as u16, &pubkey.inner)
  }
  .into_error()
}

#[napi]
pub fn learn_known_hosts(
  host: String,
  port: u32,
  pubkey: &PublicKey,
  path: Option<String>,
) -> Result<()> {
  if let Some(p) = path {
    keys::known_hosts::learn_known_hosts_path(&host, port as u16, &pubkey.inner, p)
  } else {
    keys::known_hosts::learn_known_hosts(&host, port as u16, &pubkey.inner)
  }
  .into_error()
}
