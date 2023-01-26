use std::sync::Arc;

use async_trait::async_trait;
use napi::{
  bindgen_prelude::*,
  threadsafe_function::{
    ErrorStrategy, ThreadsafeFunction, ThreadsafeFunctionCallMode, UnknownReturnValue,
  },
};
use napi_derive::napi;
use russh::client::{self, Session};
use russh_keys::{agent::client::AgentClient, key, load_secret_key};
use tokio::io::AsyncWriteExt;
#[cfg(windows)]
use tokio::net::TcpStream as SshAgentStream;
#[cfg(not(windows))]
use tokio::net::UnixStream as SshAgentStream;

use crate::{
  err::IntoError,
  keypair::{KeyPair, PublicKey},
};

#[napi]
#[derive(Debug)]
pub enum ClientIdType {
  /// When sending the id, append RFC standard `\r\n`. Example: `SshId::Standard("SSH-2.0-acme")`
  Standard,
  /// When sending the id, use this buffer as it is and do not append additional line terminators.
  Raw,
}

#[napi(object)]
/// The number of bytes read/written, and the number of seconds before a key
/// re-exchange is requested.
/// The default value Following the recommendations of
/// https://tools.ietf.org/html/rfc4253#section-9
#[derive(Debug, Clone)]
pub struct Limits {
  pub rekey_write_limit: Option<u32>,
  pub rekey_read_limit: Option<u32>,
  /// In seconds.
  pub rekey_time_limit: Option<u32>,
}

impl From<Limits> for russh::Limits {
  fn from(limits: Limits) -> Self {
    Self {
      rekey_write_limit: limits.rekey_write_limit.unwrap_or(1 << 30 /* 1GB */) as usize,
      rekey_read_limit: limits.rekey_read_limit.unwrap_or(1 << 30 /* 1GB */) as usize,
      rekey_time_limit: std::time::Duration::from_secs(
        limits.rekey_time_limit.unwrap_or(3600) as u64
      ),
    }
  }
}

#[napi(object)]
#[derive(Debug)]
pub struct ClientId {
  pub kind: ClientIdType,
  pub id: String,
}

#[napi(object)]
/// The configuration of clients.
pub struct ClientConfig {
  /// The client ID string sent at the beginning of the protocol.
  pub client_id: Option<ClientId>,
  /// The bytes and time limits before key re-exchange.
  pub limits: Option<Limits>,
  /// The initial size of a channel (used for flow control).
  pub window_size: Option<u32>,
  /// The maximal size of a single packet.
  pub maximum_packet_size: Option<u32>,
  /// Time after which the connection is garbage-collected. In milliseconds.
  pub connection_timeout: Option<u32>,
  /// Whether to expect and wait for an authentication call.
  pub anonymous: Option<bool>,
}

impl From<ClientConfig> for russh::client::Config {
  fn from(config: ClientConfig) -> Self {
    let mut russh_config = Self::default();
    if let Some(client_id) = config.client_id {
      russh_config.client_id = match client_id.kind {
        ClientIdType::Standard => russh::SshId::Standard(client_id.id),
        ClientIdType::Raw => russh::SshId::Raw(client_id.id),
      };
    }
    if let Some(limits) = config.limits {
      russh_config.limits = russh::Limits::from(limits);
    }
    if let Some(window_size) = config.window_size {
      russh_config.window_size = window_size;
    }
    if let Some(maximum_packet_size) = config.maximum_packet_size {
      russh_config.maximum_packet_size = maximum_packet_size;
    }
    russh_config.connection_timeout = config
      .connection_timeout
      .map(|timeout| std::time::Duration::from_millis(timeout as u64));
    if let Some(anonymous) = config.anonymous {
      russh_config.anonymous = anonymous;
    }
    russh_config
  }
}

#[napi(object, object_to_js = false)]
pub struct Config {
  pub client: Option<ClientConfig>,
  pub check_server_key: Option<ThreadsafeFunction<PublicKey, ErrorStrategy::Fatal>>,
  pub auth_banner: Option<ThreadsafeFunction<String, ErrorStrategy::Fatal>>,
}

pub struct ClientHandle {
  check_server_key: Option<ThreadsafeFunction<PublicKey, ErrorStrategy::Fatal>>,
  auth_banner: Option<ThreadsafeFunction<String, ErrorStrategy::Fatal>>,
}

#[async_trait]
impl russh::client::Handler for ClientHandle {
  type Error = anyhow::Error;

  async fn auth_banner(
    mut self,
    banner: &str,
    session: Session,
  ) -> std::result::Result<(Self, Session), Self::Error> {
    if let Some(on_auth_banner) = self.auth_banner.take() {
      on_auth_banner.call(banner.to_owned(), ThreadsafeFunctionCallMode::NonBlocking);
    };
    Ok((self, session))
  }

  async fn check_server_key(
    mut self,
    server_public_key: &key::PublicKey,
  ) -> std::result::Result<(Self, bool), anyhow::Error> {
    // if `auth_banner` isn't called, drop the callback
    // or it will prevent the Node.js process to exit before GC
    if self.auth_banner.is_some() {
      drop(self.auth_banner.take());
    }
    if let Some(check) = &self.check_server_key {
      let check_result: Either3<bool, Promise<bool>, UnknownReturnValue> = check
        .call_async(PublicKey::new(server_public_key.clone()))
        .await?;
      std::mem::drop(self.check_server_key.take());
      match check_result {
        Either3::A(a) => Ok((self, a)),
        Either3::B(b) => {
          let result = b.await?;
          Ok((self, result))
        }
        Either3::C(_) => Ok((self, false)),
      }
    } else {
      Ok((self, true))
    }
  }
}

#[napi]
pub struct Client {
  handle: client::Handle<ClientHandle>,
  _agent: AgentClient<SshAgentStream>,
}

#[napi]
pub async fn connect(addr: String, mut config: Option<Config>) -> Result<Client> {
  let client_config: client::Config = config
    .as_mut()
    .and_then(|c| c.client.take())
    .map(|c| c.into())
    .unwrap_or_default();
  let check_server_key = config.as_mut().and_then(|c| c.check_server_key.take());
  let auth_banner = config.as_mut().and_then(|c| c.auth_banner.take());
  let agent = AgentClient::connect_env().await.into_error()?;
  let handle = client::connect(
    Arc::new(client_config),
    addr,
    ClientHandle {
      check_server_key,
      auth_banner,
    },
  )
  .await?;
  Ok(Client::new(handle, agent))
}

#[napi]
impl Client {
  pub fn new(handle: client::Handle<ClientHandle>, agent: AgentClient<SshAgentStream>) -> Self {
    Self {
      handle,
      _agent: agent,
    }
  }

  #[napi]
  pub fn is_closed(&self) -> bool {
    self.handle.is_closed()
  }

  #[napi]
  pub async unsafe fn authenticate_password(
    &mut self,
    user: String,
    password: String,
  ) -> Result<bool> {
    self
      .handle
      .authenticate_password(user, password)
      .await
      .into_error()
  }

  #[napi]
  /// Perform public key-based SSH authentication.
  /// The key can be omitted to use the default private key.
  /// The key can be a path to a private key file.
  pub async unsafe fn authenticate_key_pair(
    &mut self,
    user: String,
    key: Either3<String, &KeyPair, Undefined>,
  ) -> Result<bool> {
    let keypair = match key {
      Either3::A(path) => load_secret_key(path, None)
        .map_err(|err| Error::new(Status::GenericFailure, format!("{err}")))?,
      Either3::B(keypair) => keypair.inner.clone(),
      Either3::C(_) => {
        let path = {
          dirs::home_dir()
            .ok_or_else(|| {
              Error::new(Status::GenericFailure, "No home directory found".to_owned())
            })?
            .join({
              #[cfg(windows)]
              {
                "ssh"
              }
              #[cfg(not(windows))]
              {
                ".ssh"
              }
            })
            .join("id_rsa")
        };
        load_secret_key(path, None)
          .map_err(|err| Error::new(Status::GenericFailure, format!("{err}")))?
      }
    };
    self
      .handle
      .authenticate_publickey(user, Arc::new(keypair))
      .await
      .into_error()
  }

  #[napi]
  pub async unsafe fn exec(&mut self, command: String) -> Result<ExecOutput> {
    let mut channel = self.handle.channel_open_session().await.into_error()?;
    channel.exec(true, command).await.into_error()?;
    let mut output = Vec::new();
    let mut status = 0;
    while let Some(msg) = channel.wait().await {
      match msg {
        russh::ChannelMsg::Data { ref data } => {
          output.write_all(data).await?;
        }
        russh::ChannelMsg::ExitStatus { exit_status } => {
          status = exit_status;
        }
        _ => {}
      }
    }
    Ok(ExecOutput {
      status,
      output: output.into(),
    })
  }

  #[napi]
  pub async fn disconnect(
    &self,
    reason: DisconnectReason,
    description: String,
    language_tag: String,
  ) -> Result<()> {
    self
      .handle
      .disconnect(reason.into(), &description, &language_tag)
      .await
      .map_err(|err| Error::new(Status::GenericFailure, format!("Disconnect failed: {err}")))?;
    Ok(())
  }
}

/// A reason for disconnection.
#[napi]
pub enum DisconnectReason {
  HostNotAllowedToConnect = 1,
  ProtocolError = 2,
  KeyExchangeFailed = 3,
  #[doc(hidden)]
  Reserved = 4,
  MACError = 5,
  CompressionError = 6,
  ServiceNotAvailable = 7,
  ProtocolVersionNotSupported = 8,
  HostKeyNotVerifiable = 9,
  ConnectionLost = 10,
  ByApplication = 11,
  TooManyConnections = 12,
  AuthCancelledByUser = 13,
  NoMoreAuthMethodsAvailable = 14,
  IllegalUserName = 15,
}

impl From<DisconnectReason> for russh::Disconnect {
  fn from(value: DisconnectReason) -> Self {
    match value {
      DisconnectReason::HostNotAllowedToConnect => Self::HostNotAllowedToConnect,
      DisconnectReason::ProtocolError => Self::ProtocolError,
      DisconnectReason::KeyExchangeFailed => Self::KeyExchangeFailed,
      DisconnectReason::Reserved => Self::Reserved,
      DisconnectReason::MACError => Self::MACError,
      DisconnectReason::CompressionError => Self::CompressionError,
      DisconnectReason::ServiceNotAvailable => Self::ServiceNotAvailable,
      DisconnectReason::ProtocolVersionNotSupported => Self::ProtocolVersionNotSupported,
      DisconnectReason::HostKeyNotVerifiable => Self::HostKeyNotVerifiable,
      DisconnectReason::ConnectionLost => Self::ConnectionLost,
      DisconnectReason::ByApplication => Self::ByApplication,
      DisconnectReason::TooManyConnections => Self::TooManyConnections,
      DisconnectReason::AuthCancelledByUser => Self::AuthCancelledByUser,
      DisconnectReason::NoMoreAuthMethodsAvailable => Self::NoMoreAuthMethodsAvailable,
      DisconnectReason::IllegalUserName => Self::IllegalUserName,
    }
  }
}

#[napi(object)]
pub struct ExecOutput {
  pub status: u32,
  pub output: Buffer,
}
