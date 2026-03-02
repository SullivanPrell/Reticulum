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
/// A TCP client interface that connects to a remote Reticulum TCP server.
///
/// This interface uses Apple's `Network.framework` (`NWConnection`) which is
/// available on iOS 12+, macOS 10.14+, and supports both Wi-Fi and cellular.
public final class TCPClientInterface: RNSInterface {

    // MARK: - RNSInterface conformance

    public let name: String
    public var `in`:  Bool = true
    public var `out`: Bool = true
    public var fwd:   Bool = false
    public var mode: InterfaceMode = .full
    public private(set) var rxb: UInt64 = 0
    public private(set) var txb: UInt64 = 0
    public weak var transport: Transport?

    // MARK: - TCP specifics

    public let host: String
    public let port: UInt16

    private var connection: NWConnection?
    private let queue: DispatchQueue
    private var receiveBuffer = Data()

    // MARK: - Initialisation

    /// Creates a TCP client interface.
    ///
    /// - Parameters:
    ///   - name:  A human-readable name for this interface.
    ///   - host:  The remote hostname or IP address.
    ///   - port:  The remote TCP port (default 4242).
    public init(name: String, host: String, port: UInt16 = 4242) {
        self.name = name
        self.host = host
        self.port = port
        self.queue = DispatchQueue(label: "rns.tcp.\(name)", qos: .utility)
    }

    // MARK: - RNSInterface

    public func start() throws {
        let endpoint   = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port)!
        )
        let params     = NWParameters.tcp
        let conn       = NWConnection(to: endpoint, using: params)
        self.connection = conn

        conn.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .ready:
                self.receiveLoop()
            case .failed(let error):
                RNSLog.error("TCPClientInterface \(self.name) failed: \(error)")
            case .cancelled:
                break
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    public func stop() {
        connection?.cancel()
        connection = nil
    }

    public func processOutbound(_ data: Data) {
        guard let conn = connection else { return }
        // HDLC-style framing: length (big-endian UInt16) || payload
        var framed = Data()
        let length = UInt16(data.count)
        framed.append(UInt8((length >> 8) & 0xFF))
        framed.append(UInt8( length       & 0xFF))
        framed += data
        conn.send(content: framed, completion: .contentProcessed { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                RNSLog.error("TCPClientInterface \(self.name) send error: \(error)")
            } else {
                self.txb += UInt64(data.count)
            }
        })
    }

    // MARK: - Private

    private func receiveLoop() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, _, error in
            guard let self = self else { return }
            if let error = error {
                RNSLog.error("TCPClientInterface \(self.name) receive error: \(error)")
                return
            }
            if let data = data, !data.isEmpty {
                self.receiveBuffer += data
                self.rxb += UInt64(data.count)
                self.parseFrames()
            }
            self.receiveLoop()
        }
    }

    private func parseFrames() {
        while receiveBuffer.count >= 2 {
            let length = Int(receiveBuffer[0]) << 8 | Int(receiveBuffer[1])
            guard receiveBuffer.count >= 2 + length else { break }
            let payload = receiveBuffer[2 ..< 2 + length]
            receiveBuffer = receiveBuffer.dropFirst(2 + length)
            transport?.inbound(data: Data(payload), interface: self)
        }
    }
}
#endif
