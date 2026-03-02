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
#if canImport(Network)
import Network
#endif

#if canImport(Network)
/// A UDP interface for sending and receiving Reticulum packets over UDP.
///
/// Each Reticulum packet is sent as a single UDP datagram.  No framing is
/// needed because UDP preserves message boundaries.  This interface supports
/// unicast (to a specific host/port) as well as local-subnet broadcast-style
/// use when combined with a loop-back receive listener.
public final class UDPInterface: RNSInterface {

    // MARK: - RNSInterface conformance

    public let name: String
    public var `in`:  Bool = true
    public var `out`: Bool = true
    public var fwd:   Bool = false
    public var mode: InterfaceMode = .full
    public private(set) var rxb: UInt64 = 0
    public private(set) var txb: UInt64 = 0
    public weak var transport: Transport?

    // MARK: - UDP specifics

    /// The remote host to which outgoing packets are sent.
    public let targetHost: String

    /// The remote UDP port to which outgoing packets are sent.
    public let targetPort: UInt16

    /// The local UDP port on which this interface listens.
    public let listenPort: UInt16

    private var listener: NWListener?
    private var sendConnection: NWConnection?
    private let queue: DispatchQueue

    // MARK: - Initialisation

    /// Creates a UDP interface.
    ///
    /// - Parameters:
    ///   - name:        Human-readable interface name.
    ///   - targetHost:  Hostname or IP to send packets to.
    ///   - targetPort:  Destination UDP port (default 4242).
    ///   - listenPort:  Local UDP port to listen on (default 4242).
    public init(
        name: String,
        targetHost: String,
        targetPort: UInt16 = 4242,
        listenPort: UInt16 = 4242
    ) {
        self.name       = name
        self.targetHost = targetHost
        self.targetPort = targetPort
        self.listenPort = listenPort
        self.queue = DispatchQueue(label: "rns.udp.\(name)", qos: .utility)
    }

    // MARK: - RNSInterface

    public func start() throws {
        try startListener()
        startSendConnection()
    }

    public func stop() {
        listener?.cancel()
        listener = nil
        sendConnection?.cancel()
        sendConnection = nil
    }

    public func processOutbound(_ data: Data) {
        guard let conn = sendConnection else { return }
        conn.send(content: data, completion: .contentProcessed { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                RNSLog.error("UDPInterface \(self.name) send error: \(error)")
            } else {
                self.txb += UInt64(data.count)
            }
        })
    }

    // MARK: - Private

    private func startListener() throws {
        let params = NWParameters.udp
        params.allowLocalEndpointReuse = true
        let port = NWEndpoint.Port(rawValue: listenPort)!
        let lstnr = try NWListener(using: params, on: port)
        self.listener = lstnr

        lstnr.newConnectionHandler = { [weak self] connection in
            guard let self = self else { return }
            self.receiveFrom(connection: connection)
        }
        lstnr.start(queue: queue)
    }

    private func startSendConnection() {
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(targetHost),
            port: NWEndpoint.Port(rawValue: targetPort)!
        )
        let conn = NWConnection(to: endpoint, using: .udp)
        self.sendConnection = conn
        conn.start(queue: queue)
    }

    private func receiveFrom(connection: NWConnection) {
        connection.start(queue: queue)
        receive(connection: connection)
    }

    private func receive(connection: NWConnection) {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self = self else { return }
            if let error = error {
                RNSLog.error("UDPInterface \(self.name) receive error: \(error)")
                return
            }
            if let data = data, !data.isEmpty {
                self.rxb += UInt64(data.count)
                self.transport?.inbound(data: data, interface: self)
            }
            // Re-arm receive for UDP listener connections
            self.receive(connection: connection)
        }
    }
}
#endif
