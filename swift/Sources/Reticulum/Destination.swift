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

/// A Reticulum network endpoint.
///
/// Destinations identify where packets should be sent and how they should be
/// encrypted.  Every destination has a deterministic hash derived from its
/// identity's public key combined with a hierarchical name (app name + aspects).
public final class Destination {

    // MARK: - Type Enumerations

    public enum DestinationType: UInt8 {
        case single = 0x00
        case group  = 0x01
        case plain  = 0x02
        case link   = 0x03
    }

    public enum Direction: UInt8 {
        case `in`  = 0x11
        case out   = 0x12
    }

    public enum ProofStrategy: UInt8 {
        case none = 0x21
        case app  = 0x22
        case all  = 0x23
    }

    // MARK: - Properties

    /// The identity associated with this destination (may be public-key-only for OUT).
    public let identity: Identity?

    public let direction: Direction
    public let type: DestinationType
    public let appName: String
    public let aspects: [String]

    /// Pre-shared key used for GROUP destinations (AES-256).
    public private(set) var groupKey: SymmetricKey?

    /// The full name of this destination: `appName.aspect1.aspect2…`
    public var fullName: String {
        ([appName] + aspects).joined(separator: ".")
    }

    /// The 80-bit name hash as ``Data`` (10 bytes).
    public var nameHash: Data {
        let nameBytes = Data(fullName.utf8)
        let fullHash  = Data(SHA256.hash(data: nameBytes))
        return fullHash.prefix(Identity.nameHashLengthBits / 8)   // 10 bytes
    }

    /// The 128-bit (16-byte) addressable destination hash.
    ///
    /// For `SINGLE` destinations this is derived from the identity's public key
    /// and the name hash, matching the Python reference implementation:
    /// `SHA-256(identity.public_key || name_hash)[0:16]`
    public var hash: Data {
        switch type {
        case .single:
            guard let id = identity else { return Data(repeating: 0, count: 16) }
            let material = id.publicKey + nameHash
            return Data(SHA256.hash(data: material)).prefix(Identity.truncatedHashLengthBits / 8)
        case .plain, .group:
            return Data(SHA256.hash(data: nameHash)).prefix(Identity.truncatedHashLengthBits / 8)
        case .link:
            return Data(repeating: 0, count: 16)
        }
    }

    /// Hex-encoded destination hash.
    public var hexHash: String { hash.hexEncodedString() }

    // MARK: - Callbacks

    /// Called when a new `Link` is established to this destination.
    public var linkEstablishedCallback: ((Link) -> Void)?

    /// Called when a plain ``Packet`` is received at this destination.
    public var packetCallback: ((Packet, Data) -> Void)?

    // MARK: - Initialisation

    /// Creates a new `Destination`.
    ///
    /// - Parameters:
    ///   - identity: The identity for this endpoint.  Pass `nil` for plain or anonymous endpoints.
    ///   - direction: Whether this is an inbound (`in`) or outbound (`out`) endpoint.
    ///   - type: The encryption/addressing type.
    ///   - appName: Application name string (no dots).
    ///   - aspects: Zero or more additional name aspects.
    public init(
        identity: Identity?,
        direction: Direction,
        type: DestinationType,
        appName: String,
        aspects: [String] = []
    ) {
        self.identity  = identity
        self.direction = direction
        self.type      = type
        self.appName   = appName
        self.aspects   = aspects
    }

    // MARK: - Group Key

    /// Sets the pre-shared key for a GROUP destination.
    ///
    /// - Parameter key: A 256-bit symmetric key.
    public func setGroupKey(_ key: SymmetricKey) {
        groupKey = key
    }

    // MARK: - Announce

    /// Builds a minimal announce packet payload for this destination.
    ///
    /// The payload is: `destination_hash (16) || identity_public_key (64) || name_hash (10) || signature (64)`
    ///
    /// - Returns: Encoded announce bytes, or `nil` if this destination cannot announce
    ///   (e.g., no private keys).
    public func buildAnnouncePayload(appData: Data? = nil) throws -> Data? {
        guard let id = identity, id.hasPrivateKey else { return nil }

        var payload = Data()
        payload += hash                  // 16 bytes
        payload += id.publicKey          // 64 bytes
        payload += nameHash              // 10 bytes

        if let appData = appData {
            payload += appData
        }

        let signature = try id.sign(message: payload)
        payload += signature             // 64 bytes

        return payload
    }
}
