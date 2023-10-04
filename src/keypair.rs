use napi::{bindgen_prelude::*, JsBuffer};
use napi_derive::napi;

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

impl From<SignatureHash> for russh_keys::key::SignatureHash {
  fn from(hash: SignatureHash) -> Self {
    match hash {
      SignatureHash::SHA1 => Self::SHA1,
      SignatureHash::SHA2_256 => Self::SHA2_256,
      SignatureHash::SHA2_512 => Self::SHA2_512,
    }
  }
}

impl SignatureHash {
  #[inline]
  fn as_bytes(&self) -> &'static [u8] {
    match self {
      Self::SHA1 => b"ssh-rsa",
      Self::SHA2_256 => b"rsa-sha2-256",
      Self::SHA2_512 => b"rsa-sha2-512",
    }
  }
}

#[napi]
pub struct PublicKey {
  inner: russh_keys::key::PublicKey,
}

#[napi]
impl PublicKey {
  pub(crate) fn new(inner: russh_keys::key::PublicKey) -> Self {
    Self { inner }
  }

  #[napi]
  pub fn name(&self) -> String {
    self.inner.name().to_string()
  }

  #[napi]
  pub fn verify_detached(&self, data: Vec<u8>, signature: Vec<u8>) -> bool {
    self.inner.verify_detached(&data, &signature)
  }

  #[napi]
  /// Compute the key fingerprint, hashed with sha2-256.
  pub fn fingerprint(&self) -> String {
    self.inner.fingerprint()
  }

  #[napi]
  /// Only effect the `RSA` PublicKey
  pub fn set_algorithm(&mut self, algorithm: SignatureHash) {
    self.inner.set_algorithm(algorithm.as_bytes());
  }
}

#[napi]
pub struct KeyPair {
  pub(crate) inner: russh_keys::key::KeyPair,
}

#[napi]
impl KeyPair {
  #[napi(factory)]
  pub fn generate_ed25519() -> Result<Self> {
    Ok(Self {
      inner: russh_keys::key::KeyPair::generate_ed25519().ok_or_else(|| {
        Error::new(
          Status::GenericFailure,
          "Generate ed25519 keypair failed".to_owned(),
        )
      })?,
    })
  }

  #[napi(factory)]
  pub fn generate_rsa(bits: u32, signature_hash: SignatureHash) -> Result<Self> {
    Ok(Self {
      inner: russh_keys::key::KeyPair::generate_rsa(bits as usize, signature_hash.into())
        .ok_or_else(|| {
          Error::new(
            Status::GenericFailure,
            "Generate rsa keypair failed".to_owned(),
          )
        })?,
    })
  }

  #[napi(constructor)]
  pub fn new(path: String, password: Option<String>) -> Result<Self> {
    Ok(Self {
      inner: russh_keys::load_secret_key(path, password.as_deref())
        .into_error()?,
    })
  }

  #[napi]
  pub fn clone_public_key(&self) -> Result<PublicKey> {
    self
      .inner
      .clone_public_key()
      .map(|public_key| PublicKey { inner: public_key })
      .into_error()
  }

  #[napi]
  pub fn name(&self) -> String {
    self.inner.name().to_string()
  }

  #[napi]
  /// Sign a slice using this algorithm.
  pub fn sign_detached(&self, to_sign: JsBuffer) -> Result<Signature> {
    self
      .inner
      .sign_detached(to_sign.into_value()?.as_ref())
      .map(|signature| Signature { inner: signature })
      .into_error()
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
    russh_keys::check_known_hosts_path(&host, port as u16, &pubkey.inner, p)
  } else {
    russh_keys::check_known_hosts(&host, port as u16, &pubkey.inner)
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
    russh_keys::learn_known_hosts_path(&host, port as u16, &pubkey.inner, p)
  } else {
    russh_keys::learn_known_hosts(&host, port as u16, &pubkey.inner)
  }
  .into_error()
}
