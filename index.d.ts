/* auto-generated by NAPI-RS */
/* eslint-disable */

export class Client {
  isClosed(): boolean
  /**
   * # Safety
   *
   * close can not be called concurrently.
   */
  authenticatePassword(user: string, password: string): Promise<boolean>
  /**
   * Perform public key-based SSH authentication.
   * The key can be omitted to use the default private key.
   * The key can be a path to a private key file.
   */
  authenticateKeyPair(user: string, key: string | KeyPair | undefined): Promise<boolean>
  /**
   * # Safety
   *
   * exec can not be called concurrently.
   * The caller in Node.js must ensure that.
   */
  exec(command: string): Promise<ExecOutput>
  disconnect(reason: DisconnectReason, description: string, languageTag: string): Promise<void>
}

export class KeyPair {
  static generateEd25519(): KeyPair
  static generateRsa(bits: number, signatureHash: SignatureHash): KeyPair
  constructor(path: string, password?: string | undefined | null)
  clonePublicKey(): PublicKey
  name(): string
  /** Sign a slice using this algorithm. */
  signDetached(toSign: Buffer): Signature
}

export class PublicKey {
  name(): string
  verifyDetached(data: Array<number>, signature: Array<number>): boolean
  /** Compute the key fingerprint, hashed with sha2-256. */
  fingerprint(): string
  /** Only effect the `RSA` PublicKey */
  setAlgorithm(algorithm: SignatureHash): void
}

export class Signature {
  toBase64(): string
}

export function checkKnownHosts(host: string, port: number, pubkey: PublicKey, path?: string | undefined | null): boolean

/** The configuration of clients. */
export interface ClientConfig {
  /** The client ID string sent at the beginning of the protocol. */
  clientId?: ClientId
  /** The bytes and time limits before key re-exchange. */
  limits?: Limits
  /** The initial size of a channel (used for flow control). */
  windowSize?: number
  /** The maximal size of a single packet. */
  maximumPacketSize?: number
  /** Time after which the connection is garbage-collected. In milliseconds. */
  inactivityTimeout?: number
  /** Whether to expect and wait for an authentication call. */
  anonymous?: boolean
}

export interface ClientId {
  kind: ClientIdType
  id: string
}

export const enum ClientIdType {
  /** When sending the id, append RFC standard `
  `. Example: `SshId::Standard("SSH-2.0-acme")` */
  Standard = 0,
  /** When sending the id, use this buffer as it is and do not append additional line terminators. */
  Raw = 1
}

export interface Config {
  client?: ClientConfig
  checkServerKey?: (arg: PublicKey) => any
  authBanner?: (arg: string) => any
}

export function connect(addr: string, config?: Config | undefined | null): Promise<Client>

/** A reason for disconnection. */
export const enum DisconnectReason {
  HostNotAllowedToConnect = 1,
  ProtocolError = 2,
  KeyExchangeFailed = 3,
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
  IllegalUserName = 15
}

export interface ExecOutput {
  status: number
  output: Buffer
}

export function learnKnownHosts(host: string, port: number, pubkey: PublicKey, path?: string | undefined | null): void

/**
 * The number of bytes read/written, and the number of seconds before a key
 * re-exchange is requested.
 * The default value Following the recommendations of
 * https://tools.ietf.org/html/rfc4253#section-9
 */
export interface Limits {
  rekeyWriteLimit?: number
  rekeyReadLimit?: number
  /** In seconds. */
  rekeyTimeLimit?: number
}

/** The hash function used for signing with RSA keys. */
export const enum SignatureHash {
  /** SHA2, 256 bits. */
  SHA2_256 = 0,
  /** SHA2, 512 bits. */
  SHA2_512 = 1,
  /** SHA1 */
  SHA1 = 2
}

