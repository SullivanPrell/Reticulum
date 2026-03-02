// Reticulum License
//
// Copyright (c) 2016-2025 Mark Qvist
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// - The Software shall not be used in any kind of system which includes amongst
//   its functions the ability to purposefully do harm to human beings.
//
// - The Software shall not be used, directly or indirectly, in the creation of
//   an artificial intelligence, machine learning or language model training
//   dataset, including but not limited to any use that contributes to the
//   training or development of such a model or algorithm.
//
// - The above copyright notice and this permission notice shall be included in
//   all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import Foundation
import Crypto

/// `Identity` manages the cryptographic identity of a Reticulum node.
///
/// Each identity holds an X25519 key pair for ECDH encryption and an
/// Ed25519 key pair for signing.  A complete public key is the 64-byte
/// concatenation of the X25519 public key (32 bytes) and the Ed25519
/// public key (32 bytes), which matches the Python reference implementation.
public final class Identity {

    // MARK: - Constants

    /// Curve used for Elliptic Curve DH key exchanges.
    public static let curve = "Curve25519"

    /// Full key size in bits (256-bit encryption key + 256-bit signing key).
    public static let keySizeBits = 512

    /// Hash length in bits.
    public static let hashLengthBits = 256

    /// Truncated hash length in bits (matches ``Reticulum.truncatedHashLength``).
    public static let truncatedHashLengthBits = 128

    /// Signature length in bits.
    public static let signatureLengthBits = 512

    /// Name hash length in bits (used when deriving destination hashes).
    public static let nameHashLengthBits = 80

    // MARK: - Storage

    /// A thread-safe registry of known remote identities keyed by
    /// truncated destination hash.
    private static var knownDestinations: [Data: Identity] = [:]
    private static let lock = NSLock()

    // MARK: - Keys

    /// X25519 private key – `nil` for outbound-only (public-key-only) identities.
    private let encryptionPrivateKey: Curve25519.KeyAgreement.PrivateKey?

    /// Ed25519 private key – `nil` for outbound-only identities.
    private let signingPrivateKey: Curve25519.Signing.PrivateKey?

    /// X25519 public key (always present).
    public let encryptionPublicKey: Curve25519.KeyAgreement.PublicKey

    /// Ed25519 public key (always present).
    public let signingPublicKey: Curve25519.Signing.PublicKey

    // MARK: - Initialisation

    /// Creates a new `Identity` with freshly generated key pairs.
    public init() {
        let ekPriv = Curve25519.KeyAgreement.PrivateKey()
        let skPriv = Curve25519.Signing.PrivateKey()
        encryptionPrivateKey = ekPriv
        signingPrivateKey    = skPriv
        encryptionPublicKey  = ekPriv.publicKey
        signingPublicKey     = skPriv.publicKey
    }

    /// Creates a public-key-only identity from a 64-byte public-key blob.
    ///
    /// - Parameter publicKeyData: 32 bytes X25519 || 32 bytes Ed25519.
    /// - Throws: `IdentityError` if the data is malformed.
    public init(publicKeyData: Data) throws {
        guard publicKeyData.count == 64 else {
            throw IdentityError.invalidPublicKeyLength(publicKeyData.count)
        }
        let ekBytes = publicKeyData.prefix(32)
        let skBytes = publicKeyData.suffix(32)
        encryptionPublicKey  = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ekBytes)
        signingPublicKey     = try Curve25519.Signing.PublicKey(rawRepresentation: skBytes)
        encryptionPrivateKey = nil
        signingPrivateKey    = nil
    }

    /// Creates a full identity from a 64-byte private-key blob (32 bytes X25519 || 32 bytes Ed25519).
    ///
    /// - Parameter privateKeyData: Raw concatenated private key bytes.
    /// - Throws: `IdentityError` if the data is malformed.
    public init(privateKeyData: Data) throws {
        guard privateKeyData.count == 64 else {
            throw IdentityError.invalidPrivateKeyLength(privateKeyData.count)
        }
        let ekPriv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData.prefix(32))
        let skPriv = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData.suffix(32))
        encryptionPrivateKey = ekPriv
        signingPrivateKey    = skPriv
        encryptionPublicKey  = ekPriv.publicKey
        signingPublicKey     = skPriv.publicKey
    }

    // MARK: - Serialisation

    /// The full 64-byte public key blob (X25519 || Ed25519).
    public var publicKey: Data {
        Data(encryptionPublicKey.rawRepresentation) +
        Data(signingPublicKey.rawRepresentation)
    }

    /// The full 64-byte private key blob (X25519 || Ed25519).
    /// - Throws: `IdentityError.noPrivateKey` if this is a public-key-only identity.
    public func privateKey() throws -> Data {
        guard let ek = encryptionPrivateKey, let sk = signingPrivateKey else {
            throw IdentityError.noPrivateKey
        }
        return Data(ek.rawRepresentation) + Data(sk.rawRepresentation)
    }

    /// Whether this identity holds private keys.
    public var hasPrivateKey: Bool { encryptionPrivateKey != nil }

    // MARK: - Hashing

    /// SHA-256 hash of the public key.
    public var hash: Data {
        Data(SHA256.hash(data: publicKey))
    }

    /// Truncated hash used as the addressable hash (first 16 bytes = 128 bits).
    public var truncatedHash: Data {
        hash.prefix(Identity.truncatedHashLengthBits / 8)
    }

    /// Hex-encoded truncated hash, used as a human-readable address.
    public var hexHash: String {
        truncatedHash.hexEncodedString()
    }

    // MARK: - Encryption / Decryption

    /// Encrypts `plaintext` addressed to this identity using an ephemeral
    /// X25519 ECDH exchange and AES-256-GCM (matching the Python Token).
    ///
    /// - Parameter plaintext: Raw bytes to encrypt.
    /// - Returns: Encrypted token bytes.
    /// - Throws: `IdentityError` on cryptographic failure.
    public func encrypt(plaintext: Data) throws -> Data {
        let ephemeralPrivate = Curve25519.KeyAgreement.PrivateKey()
        let sharedSecret = try ephemeralPrivate.sharedSecretFromKeyAgreement(with: encryptionPublicKey)

        // Derive a 32-byte key via HKDF-SHA256 (no salt, no info – matches reference)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(),
            outputByteCount: 32
        )

        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: nonce)

        // token = ephemeral_pub (32) || nonce (12) || ciphertext || tag (16)
        let ephemeralPub = Data(ephemeralPrivate.publicKey.rawRepresentation)
        return ephemeralPub + Data(nonce) + sealed.ciphertext + sealed.tag
    }

    /// Decrypts a token produced by ``encrypt(plaintext:)``.
    ///
    /// - Parameter token: Encrypted token bytes.
    /// - Returns: Decrypted plaintext, or `nil` if decryption fails.
    /// - Throws: `IdentityError.noPrivateKey` if this is a public-key-only identity.
    public func decrypt(token: Data) throws -> Data? {
        guard let ekPriv = encryptionPrivateKey else {
            throw IdentityError.noPrivateKey
        }
        guard token.count >= 32 + 12 + 16 else { return nil }

        let ephemeralPubBytes = token.prefix(32)
        let remainder         = token.dropFirst(32)
        let nonceBytes        = remainder.prefix(12)
        let ciphertextAndTag  = remainder.dropFirst(12)

        guard ciphertextAndTag.count >= 16 else { return nil }
        let ciphertext = ciphertextAndTag.dropLast(16)
        let tag        = ciphertextAndTag.suffix(16)

        let ephemeralPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPubBytes)
        let sharedSecret = try ekPriv.sharedSecretFromKeyAgreement(with: ephemeralPub)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(),
            outputByteCount: 32
        )

        let nonce  = try AES.GCM.Nonce(data: nonceBytes)
        let box    = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(box, using: symmetricKey)
    }

    // MARK: - Signing / Verification

    /// Signs `message` with the Ed25519 signing key.
    ///
    /// - Parameter message: Data to sign.
    /// - Returns: 64-byte signature.
    /// - Throws: `IdentityError.noPrivateKey` if this is a public-key-only identity.
    public func sign(message: Data) throws -> Data {
        guard let skPriv = signingPrivateKey else {
            throw IdentityError.noPrivateKey
        }
        let signature = try skPriv.signature(for: message)
        return Data(signature)
    }

    /// Verifies an Ed25519 `signature` over `message` using this identity's
    /// public signing key.
    public func validate(signature: Data, for message: Data) -> Bool {
        signingPublicKey.isValidSignature(signature, for: message)
    }

    // MARK: - Known Destinations Registry

    /// Records a remote identity so it can be looked up by its truncated hash.
    public static func remember(
        identity: Identity,
        destinationHash: Data,
        appData: Data? = nil
    ) {
        lock.lock()
        defer { lock.unlock() }
        knownDestinations[destinationHash] = identity
    }

    /// Returns the identity associated with `destinationHash`, if known.
    public static func recall(destinationHash: Data) -> Identity? {
        lock.lock()
        defer { lock.unlock() }
        return knownDestinations[destinationHash]
    }

    /// Removes all remembered remote identities.
    public static func forgetAll() {
        lock.lock()
        defer { lock.unlock() }
        knownDestinations.removeAll()
    }

    // MARK: - Persistence

    #if canImport(Security)
    /// Saves the private key to the iOS / macOS Keychain under `account`.
    ///
    /// - Parameters:
    ///   - account: A unique string identifying this key in the Keychain.
    /// - Throws: `IdentityError` on Keychain failure or if no private key is present.
    public func saveToKeychain(account: String) throws {
        let privKey = try privateKey()
        let query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrAccount: account,
            kSecValueData:   privKey,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlock,
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw IdentityError.keychainError(status)
        }
    }

    /// Loads an `Identity` from the Keychain using `account`.
    ///
    /// - Returns: A fully initialised identity, or `nil` if not found.
    /// - Throws: `IdentityError` on Keychain failure.
    public static func loadFromKeychain(account: String) throws -> Identity? {
        let query: [CFString: Any] = [
            kSecClass:            kSecClassGenericPassword,
            kSecAttrAccount:      account,
            kSecReturnData:       true,
            kSecMatchLimit:       kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw IdentityError.keychainError(status)
        }
        return try Identity(privateKeyData: data)
    }
    #endif
}

// MARK: - Errors

/// Errors thrown by `Identity` operations.
public enum IdentityError: Error, LocalizedError {
    case invalidPublicKeyLength(Int)
    case invalidPrivateKeyLength(Int)
    case noPrivateKey
    #if canImport(Security)
    case keychainError(OSStatus)
    #endif

    public var errorDescription: String? {
        switch self {
        case .invalidPublicKeyLength(let n):
            return "Invalid public key length: expected 64 bytes, got \(n)."
        case .invalidPrivateKeyLength(let n):
            return "Invalid private key length: expected 64 bytes, got \(n)."
        case .noPrivateKey:
            return "This identity does not hold private keys."
        #if canImport(Security)
        case .keychainError(let status):
            return "Keychain error with OSStatus \(status)."
        #endif
        }
    }
}
