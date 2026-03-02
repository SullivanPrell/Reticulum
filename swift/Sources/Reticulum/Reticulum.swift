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

/// The main entry point for the Reticulum network stack.
///
/// Create exactly one `Reticulum` instance per process.  Add interfaces, register
/// destinations and then call ``start()`` to bring the stack online.
///
/// ```swift
/// let rns = Reticulum()
/// let iface = TCPClientInterface(name: "MyTCP", host: "192.168.1.1")
/// rns.addInterface(iface)
///
/// let identity = Identity()
/// let destination = Destination(
///     identity: identity,
///     direction: .in,
///     type: .single,
///     appName: "myapp",
///     aspects: ["hello"]
/// )
/// rns.registerDestination(destination)
/// try rns.start()
/// ```
public final class Reticulum {

    // MARK: - Constants

    /// The default maximum transmission unit in bytes.
    public static let mtu = 500

    /// Length (in bits) of truncated hashes used as addressable identifiers.
    public static let truncatedHashLength = 128

    // MARK: - Properties

    /// The underlying transport layer.
    public let transport: Transport

    private var isRunning = false

    // MARK: - Initialisation

    public init() {
        self.transport = Transport()
    }

    // MARK: - Interface Management

    /// Adds a network interface to the stack.
    public func addInterface(_ iface: any RNSInterface) {
        transport.addInterface(iface)
    }

    // MARK: - Destination Management

    /// Registers a local destination so inbound packets can be dispatched to it.
    public func registerDestination(_ destination: Destination) {
        transport.registerDestination(destination)
    }

    // MARK: - Lifecycle

    /// Starts all registered interfaces.
    ///
    /// - Throws: Any error thrown by an interface's ``RNSInterface/start()`` method.
    public func start() throws {
        guard !isRunning else { return }
        for iface in transport.interfaces {
            try iface.start()
        }
        isRunning = true
        RNSLog.info("Reticulum started with \(transport.interfaces.count) interface(s).")
    }

    /// Stops all registered interfaces.
    public func stop() {
        guard isRunning else { return }
        for iface in transport.interfaces {
            iface.stop()
        }
        isRunning = false
        RNSLog.info("Reticulum stopped.")
    }

    // MARK: - Sending

    /// Sends `data` to a destination.
    ///
    /// - Parameters:
    ///   - data:        Payload bytes (must fit within ``mtu`` after header overhead).
    ///   - destination: The destination to address the packet to.
    public func send(data: Data, to destination: Destination) {
        let packet = Packet(
            destinationHash: destination.hash,
            data: data,
            packetType: .data,
            context: .none,
            transportType: .broadcast,
            headerType: .header1,
            destinationType: destination.type
        )
        transport.send(packet: packet)
    }

    /// Broadcasts an announce for the given destination.
    ///
    /// - Parameters:
    ///   - destination: The local (IN) destination to announce.
    ///   - appData:     Optional additional data to include in the announce.
    public func announce(destination: Destination, appData: Data? = nil) throws {
        guard let payload = try destination.buildAnnouncePayload(appData: appData) else {
            RNSLog.error("Cannot announce destination without private identity keys.")
            return
        }
        let packet = Packet(
            destinationHash: destination.hash,
            data: payload,
            packetType: .announce,
            context: .none,
            transportType: .broadcast,
            headerType: .header1,
            destinationType: destination.type
        )
        transport.send(packet: packet)
    }
}
