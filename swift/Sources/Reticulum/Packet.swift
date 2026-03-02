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

/// A Reticulum packet.
///
/// Packets carry data between Reticulum nodes.  This class handles encoding and
/// decoding of the binary wire format defined by the Reticulum specification.
///
/// ## Wire format (HEADER_1)
/// ```
/// Byte 0:  [header flags]
///   bits 7-6: header type (00 = HEADER_1, 01 = HEADER_2)
///   bits 5-4: transport type (00=BROADCAST, 01=TRANSPORT, 10=RELAY, 11=TUNNEL)
///   bits 3-2: destination type (00=SINGLE, 01=GROUP, 10=PLAIN, 11=LINK)
///   bits 1-0: packet type (00=DATA, 01=ANNOUNCE, 10=LINKREQUEST, 11=PROOF)
/// Byte 1:  hop count
/// Bytes 2…17:  destination hash (16 bytes)
/// Byte 18: context byte
/// Bytes 19…end: data payload
/// ```
public final class Packet {

    // MARK: - Constants

    public static let mtu = 500

    // MARK: - Packet types

    public enum PacketType: UInt8 {
        case data        = 0x00
        case announce    = 0x01
        case linkRequest = 0x02
        case proof       = 0x03
    }

    // MARK: - Header types

    public enum HeaderType: UInt8 {
        case header1 = 0x00   // Normal
        case header2 = 0x01   // In-transport
    }

    // MARK: - Transport types

    public enum TransportType: UInt8 {
        case broadcast = 0x00
        case transport = 0x01
        case relay     = 0x02
        case tunnel    = 0x03
    }

    // MARK: - Context types

    public enum Context: UInt8 {
        case none         = 0x00
        case resource     = 0x01
        case resourceAdv  = 0x02
        case resourceReq  = 0x03
        case resourceHmu  = 0x04
        case resourcePrf  = 0x05
        case resourceIcl  = 0x06
        case resourceRcl  = 0x07
        case cacheRequest = 0x08
        case requestRttProbe = 0x09
        case requestProof = 0x0F
        case linkIdentify = 0xA0
        case linkClose    = 0xA1
        case linkProof    = 0xA2
        case linkRttProbe = 0xA3
        case linkRequest  = 0xA4
    }

    // MARK: - Properties

    public let headerType: HeaderType
    public let transportType: TransportType
    public let destinationType: Destination.DestinationType
    public let packetType: PacketType
    public let context: Context
    public var hopCount: UInt8
    public let destinationHash: Data    // 16 bytes
    public var transportID: Data?       // 16 bytes, only for HEADER_2
    public let data: Data

    /// Whether this packet has already been sent.
    public private(set) var sent: Bool = false

    /// The wire-format hash of this packet (SHA-256 of raw bytes, truncated to 16 bytes).
    public var packetHash: Data {
        let raw = toBytes()
        return Data(SHA256.hash(data: raw)).prefix(16)
    }

    // MARK: - Initialisation

    /// Creates a new packet.
    public init(
        destinationHash: Data,
        data: Data,
        packetType: PacketType = .data,
        context: Context = .none,
        transportType: TransportType = .broadcast,
        headerType: HeaderType = .header1,
        destinationType: Destination.DestinationType = .single,
        transportID: Data? = nil,
        hopCount: UInt8 = 0
    ) {
        self.destinationHash = destinationHash
        self.data            = data
        self.packetType      = packetType
        self.context         = context
        self.transportType   = transportType
        self.headerType      = headerType
        self.destinationType = destinationType
        self.transportID     = transportID
        self.hopCount        = hopCount
    }

    // MARK: - Encoding

    /// Encodes the packet into its binary wire representation.
    public func toBytes() -> Data {
        var bytes = Data()

        // Byte 0: flags
        let flags: UInt8 =
            (headerType.rawValue      << 6) |
            (transportType.rawValue   << 4) |
            (destinationType.rawValue << 2) |
             packetType.rawValue
        bytes.append(flags)

        // Byte 1: hop count
        bytes.append(hopCount)

        if headerType == .header2 {
            // HEADER_2: transport ID (16 bytes) before destination hash
            if let tid = transportID, tid.count == 16 {
                bytes += tid
            } else {
                bytes += Data(repeating: 0, count: 16)
            }
        }

        // Destination hash (16 bytes)
        let destHashPadded = destinationHash.prefix(16)
        bytes += destHashPadded
        if destHashPadded.count < 16 {
            bytes += Data(repeating: 0, count: 16 - destHashPadded.count)
        }

        // Context byte
        bytes.append(context.rawValue)

        // Payload
        bytes += data

        return bytes
    }

    // MARK: - Decoding

    /// Decodes a ``Packet`` from raw wire bytes.
    ///
    /// - Parameter bytes: Raw bytes received from the wire.
    /// - Returns: A decoded `Packet`, or `nil` if the bytes are too short or malformed.
    public static func fromBytes(_ bytes: Data) -> Packet? {
        guard bytes.count >= 19 else { return nil }

        let flags           = bytes[bytes.startIndex]
        let rawHeaderType   = (flags >> 6) & 0x03
        let rawTransport    = (flags >> 4) & 0x03
        let rawDestType     = (flags >> 2) & 0x03
        let rawPacketType   =  flags       & 0x03

        guard let headerType   = HeaderType(rawValue: rawHeaderType),
              let transportType = TransportType(rawValue: rawTransport),
              let destType      = Destination.DestinationType(rawValue: rawDestType),
              let packetType    = PacketType(rawValue: rawPacketType)
        else { return nil }

        let hopCount = bytes[bytes.startIndex + 1]
        var offset   = bytes.startIndex + 2

        var transportID: Data?
        if headerType == .header2 {
            guard bytes.count >= offset + 16 else { return nil }
            transportID = bytes[offset ..< offset + 16]
            offset += 16
        }

        guard bytes.count >= offset + 16 + 1 else { return nil }
        let destinationHash = bytes[offset ..< offset + 16]
        offset += 16

        let contextByte = bytes[offset]
        offset += 1
        let context = Context(rawValue: contextByte) ?? .none

        let payload = bytes[offset...]

        return Packet(
            destinationHash: Data(destinationHash),
            data: Data(payload),
            packetType: packetType,
            context: context,
            transportType: transportType,
            headerType: headerType,
            destinationType: destType,
            transportID: transportID,
            hopCount: hopCount
        )
    }

    // MARK: - Sending

    /// Marks the packet as sent (called by ``Transport`` after delivery).
    internal func markSent() { sent = true }
}
