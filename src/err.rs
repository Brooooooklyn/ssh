pub(crate) trait IntoError {
  type Value;

  fn into_error(self) -> Result<Self::Value, napi::Error>;
}

impl<T> IntoError for Result<T, russh::Error> {
  type Value = T;

  fn into_error(self) -> napi::Result<Self::Value> {
    self.map_err(|err| napi::Error::new(napi::Status::GenericFailure, err.to_string()))
  }
}

impl<T> IntoError for Result<T, russh_keys::Error> {
  type Value = T;

  fn into_error(self) -> napi::Result<Self::Value> {
    self.map_err(|err| napi::Error::new(napi::Status::GenericFailure, err.to_string()))
  }
}
