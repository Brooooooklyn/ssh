use napi_derive::napi;
use russh::keys::ssh_key::SshSig;

#[napi]
pub struct Signature {
  pub(crate) inner: SshSig,
}

#[napi]
impl Signature {
  #[napi]
  pub fn to_base64(&self) -> String {
    use base64::Engine;
    use russh::keys::ssh_encoding::Encode;
    let mut buf = Vec::new();
    self.inner.encode(&mut buf).unwrap_or_default();
    base64::prelude::BASE64_STANDARD.encode(&buf)
  }
}
