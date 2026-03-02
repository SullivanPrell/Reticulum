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

/// A verified, encrypted link between two Reticulum nodes.
///
/// When a link request is initiated, the initiator generates an ephemeral
/// X25519 key pair and sends a ``Packet/PacketType/linkRequest`` packet.
/// Once the responder replies with a proof, the link is established and
/// both sides derive a shared session key used for subsequent data packets.
public final class Link {

    // MARK: - State

    public enum State {
        case pending
        case handshake
        case active
        case closed
        case failed
    }

    // MARK: - Constants

    /// Seconds after which an idle link is considered stale.
    public static let staleTime: TimeInterval = 600

    /// Seconds after which a pending link request times out.
    public static let requestTimeout: TimeInterval = 15

    // MARK: - Properties

    /// The destination this link is established toward.
    public let destination: Destination

    public private(set) var state: State = .pending
    public private(set) var established: Date?
    public private(set) var lastActivity: Date = Date()

    /// The 16-byte link ID derived from the link request public key.
    public private(set) var linkID: Data = Data()

    /// Called when the link reaches the `.active` state.
    public var linkEstablishedCallback: ((Link) -> Void)?

    /// Called when the link is closed.
    public var linkClosedCallback: ((Link) -> Void)?

    /// Called when a data packet is received over the link.
    public var packetCallback: ((Packet, Data) -> Void)?

    // MARK: - Ephemeral keys (initiator side)

    private let ephemeralPrivate: Curve25519.KeyAgreement.PrivateKey

    /// The 32-byte public key included in the link-request packet.
    public var ephemeralPublicKey: Data {
        Data(ephemeralPrivate.publicKey.rawRepresentation)
    }

    /// Symmetric session key derived after the handshake completes.
    public private(set) var sessionKey: SymmetricKey?

    // MARK: - Initialisation

    /// Initiates a link toward `destination`.
    public init(destination: Destination) {
        self.destination = destination
        self.ephemeralPrivate = Curve25519.KeyAgreement.PrivateKey()
        // The link ID is the truncated SHA-256 of the ephemeral public key
        let pub = Data(ephemeralPrivate.publicKey.rawRepresentation)
        linkID = Data(SHA256.hash(data: pub)).prefix(16)
    }

    // MARK: - Handshake

    /// Builds the link-request packet payload.
    ///
    /// Payload: `ephemeral_public_key (32)`
    public func buildRequestPacket() -> Packet {
        Packet(
            destinationHash: destination.hash,
            data: ephemeralPublicKey,
            packetType: .linkRequest,
            context: .linkRequest,
            transportType: .broadcast,
            headerType: .header1,
            destinationType: .single
        )
    }

    /// Called by the responder to derive the shared session key after receiving
    /// the link-request and verifying the proof.
    ///
    /// - Parameter responderPublicKeyData: The 32-byte ephemeral public key from
    ///   the responder's link-proof packet.
    public func deriveSessionKey(responderPublicKeyData: Data) throws {
        let responderPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: responderPublicKeyData)
        let sharedSecret = try ephemeralPrivate.sharedSecretFromKeyAgreement(with: responderPub)
        sessionKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: linkID,
            sharedInfo: Data("reticulum_link_key".utf8),
            outputByteCount: 32
        )
        state       = .active
        established = Date()
        linkEstablishedCallback?(self)
    }

    // MARK: - Activity

    func recordActivity() {
        lastActivity = Date()
    }

    /// Returns `true` if the link has been idle longer than ``staleTime``.
    public var isStale: Bool {
        Date().timeIntervalSince(lastActivity) > Self.staleTime
    }

    // MARK: - Closure

    /// Tears down the link.
    public func close() {
        state = .closed
        linkClosedCallback?(self)
    }
}
