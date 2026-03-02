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

/// The Reticulum transport layer.
///
/// `Transport` manages all registered ``RNSInterface`` instances and routes
/// incoming packets to the appropriate local ``Destination`` or forwards them
/// onward through the network.
///
/// This implementation covers:
/// - Duplicate-packet detection via a packet-hash set.
/// - Announce handling: verifying the signature and updating ``Identity``'s
///   known-destination registry.
/// - Data-packet dispatch to registered local destinations.
/// - Forwarding of transit packets via other interfaces (when acting as a
///   transport node).
public final class Transport {

    // MARK: - Constants

    public static let pathfinderM = 128   // Max hops

    // MARK: - State

    private let lock = NSLock()

    /// All registered network interfaces.
    public private(set) var interfaces: [any RNSInterface] = []

    /// All registered local destinations.
    public private(set) var destinations: [Destination] = []

    /// Pending (not yet established) links.
    public private(set) var pendingLinks: [Link] = []

    /// Active (established) links.
    public private(set) var activeLinks: [Link] = []

    /// Packet-hash set for duplicate detection.
    private var packetHashlist = Set<Data>()

    /// Path table: maps destination hash → interface name
    private var pathTable: [Data: String] = [:]

    // MARK: - Initialisation

    public init() {}

    // MARK: - Interface Management

    /// Registers an interface with the transport.
    public func addInterface(_ iface: any RNSInterface) {
        lock.lock(); defer { lock.unlock() }
        let mutable = iface
        mutable.transport = self
        interfaces.append(mutable)
    }

    // MARK: - Destination Management

    /// Registers a local destination so that incoming packets can be dispatched.
    public func registerDestination(_ destination: Destination) {
        lock.lock(); defer { lock.unlock() }
        destinations.append(destination)
    }

    // MARK: - Outbound

    /// Sends a ``Packet`` over all suitable outbound interfaces.
    ///
    /// - Parameter packet: The packet to send.
    public func send(packet: Packet) {
        let bytes = packet.toBytes()
        guard bytes.count <= Reticulum.mtu else {
            RNSLog.error("Transport: packet exceeds MTU (\(bytes.count) > \(Reticulum.mtu)), dropping.")
            return
        }
        lock.lock()
        let ifaces = interfaces
        lock.unlock()
        for iface in ifaces where iface.out {
            iface.processOutbound(bytes)
        }
        packet.markSent()
    }

    // MARK: - Inbound

    /// Called by an interface when raw bytes arrive.
    ///
    /// - Parameters:
    ///   - data:      Raw packet bytes.
    ///   - interface: The interface on which the data arrived.
    public func inbound(data: Data, interface iface: any RNSInterface) {
        guard let packet = Packet.fromBytes(data) else {
            RNSLog.debug("Transport: could not decode packet, dropping.")
            return
        }

        // Duplicate detection
        let pHash = packet.packetHash
        lock.lock()
        let isDuplicate = packetHashlist.contains(pHash)
        if !isDuplicate { packetHashlist.insert(pHash) }
        lock.unlock()
        if isDuplicate { return }

        // Enforce max hops
        if packet.hopCount >= UInt8(Self.pathfinderM) { return }

        switch packet.packetType {
        case .announce:
            handleAnnounce(packet: packet, interface: iface)
        case .data:
            handleData(packet: packet, interface: iface)
        case .linkRequest:
            handleLinkRequest(packet: packet, interface: iface)
        case .proof:
            handleProof(packet: packet, interface: iface)
        }
    }

    // MARK: - Announce Handling

    private func handleAnnounce(packet: Packet, interface iface: any RNSInterface) {
        let payload = packet.data
        // Announce payload: dest_hash(16) || public_key(64) || name_hash(10) || [app_data] || signature(64)
        guard payload.count >= 16 + 64 + 10 + 64 else {
            RNSLog.debug("Transport: announce too short.")
            return
        }

        let destHash  = payload.prefix(16)
        let pubKey    = payload[16 ..< 80]
        // Remaining bytes before the last 64 are optional app_data + name_hash
        let sigOffset = payload.count - 64
        let signature = payload.suffix(64)
        let signed    = payload.prefix(sigOffset)

        guard let identity = try? Identity(publicKeyData: Data(pubKey)) else { return }
        guard identity.validate(signature: Data(signature), for: Data(signed)) else {
            RNSLog.debug("Transport: announce signature invalid.")
            return
        }

        Identity.remember(identity: identity, destinationHash: Data(destHash))
        updatePath(destinationHash: Data(destHash), via: iface.name)
        rebroadcastAnnounce(packet: packet, interface: iface)
    }

    // MARK: - Data Handling

    private func handleData(packet: Packet, interface iface: any RNSInterface) {
        let destHash = packet.destinationHash
        lock.lock()
        let dests = destinations
        lock.unlock()

        if let dest = dests.first(where: { $0.hash == destHash }) {
            dest.packetCallback?(packet, packet.data)
            return
        }

        // Not for a local destination – forward if we know a path
        forwardPacket(packet: packet, inboundInterface: iface)
    }

    // MARK: - Link Handling

    private func handleLinkRequest(packet: Packet, interface iface: any RNSInterface) {
        let destHash = packet.destinationHash
        lock.lock()
        let dests = destinations
        lock.unlock()

        guard let dest = dests.first(where: { $0.hash == destHash }) else {
            forwardPacket(packet: packet, inboundInterface: iface)
            return
        }

        // Build a new Link (responder side) and notify the destination
        let link = Link(destination: dest)
        dest.linkEstablishedCallback?(link)
    }

    private func handleProof(packet: Packet, interface iface: any RNSInterface) {
        // Match proof to a pending link and complete the handshake
        lock.lock()
        let pending = pendingLinks
        lock.unlock()

        guard let link = pending.first(where: { $0.linkID == packet.destinationHash }) else {
            return
        }
        guard packet.data.count >= 32 else { return }
        let responderPub = packet.data.prefix(32)
        try? link.deriveSessionKey(responderPublicKeyData: Data(responderPub))
        lock.lock()
        pendingLinks.removeAll { $0.linkID == link.linkID }
        activeLinks.append(link)
        lock.unlock()
    }

    // MARK: - Forwarding

    private func forwardPacket(packet: Packet, inboundInterface: any RNSInterface) {
        guard packet.hopCount < UInt8(Self.pathfinderM) else { return }

        // Build a new packet with incremented hop count
        let forwarded = Packet(
            destinationHash: packet.destinationHash,
            data: packet.data,
            packetType: packet.packetType,
            context: packet.context,
            transportType: .transport,
            headerType: .header2,
            destinationType: packet.destinationType,
            transportID: packet.destinationHash,
            hopCount: packet.hopCount + 1
        )
        let bytes = forwarded.toBytes()

        lock.lock()
        let ifaces = interfaces
        lock.unlock()

        for iface in ifaces where iface.out && iface.name != inboundInterface.name {
            iface.processOutbound(bytes)
        }
    }

    private func rebroadcastAnnounce(packet: Packet, interface inboundInterface: any RNSInterface) {
        let forwarded = Packet(
            destinationHash: packet.destinationHash,
            data: packet.data,
            packetType: .announce,
            context: packet.context,
            transportType: .broadcast,
            headerType: .header1,
            destinationType: .single,
            hopCount: packet.hopCount + 1
        )
        let bytes = forwarded.toBytes()

        lock.lock()
        let ifaces = interfaces
        lock.unlock()

        for iface in ifaces where iface.out && iface.name != inboundInterface.name {
            iface.processOutbound(bytes)
        }
    }

    // MARK: - Path Table

    private func updatePath(destinationHash: Data, via interfaceName: String) {
        lock.lock(); defer { lock.unlock() }
        pathTable[destinationHash] = interfaceName
    }

    public func hasPath(to destinationHash: Data) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return pathTable[destinationHash] != nil
    }
}
