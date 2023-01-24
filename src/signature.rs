use napi_derive::napi;

#[napi]
pub struct Signature {
  pub(crate) inner: russh_keys::key::Signature,
}

#[napi]
impl Signature {
  #[napi]
  pub fn to_base64(&self) -> String {
    self.inner.to_base64()
  }
}
