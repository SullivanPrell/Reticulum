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

// MARK: - Interface protocol

/// Abstract base protocol for all Reticulum network interfaces.
///
/// Implementations provide connectivity to physical or virtual network segments
/// (TCP, UDP, Bluetooth, LoRa, etc.).  Each interface passes received bytes to
/// ``Transport`` which handles routing and packet dispatch.
public protocol RNSInterface: AnyObject {

    /// Human-readable interface name (used in logs and config).
    var name: String { get }

    /// Whether this interface accepts inbound packets.
    var `in`: Bool { get set }

    /// Whether this interface sends outbound packets.
    var `out`: Bool { get set }

    /// Whether this interface forwards (transport node behaviour).
    var fwd: Bool { get set }

    /// Interface operating mode.
    var mode: InterfaceMode { get set }

    /// Bytes received.
    var rxb: UInt64 { get }

    /// Bytes transmitted.
    var txb: UInt64 { get }

    /// The ``Transport`` instance this interface is attached to.
    var transport: Transport? { get set }

    /// Send `data` over the interface.
    func processOutbound(_ data: Data)

    /// Start the interface (open connections/sockets).
    func start() throws

    /// Stop the interface (close connections/sockets).
    func stop()
}

// MARK: - InterfaceMode

public enum InterfaceMode {
    case full
    case pointToPoint
    case accessPoint
    case roaming
    case boundary
    case gateway
}
