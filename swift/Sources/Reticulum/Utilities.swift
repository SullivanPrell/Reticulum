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
#if canImport(os)
import os.log
#endif

/// Simple logging helper used across the Reticulum Swift package.
///
/// On Apple platforms this forwards to `os.log` so that messages appear in
/// Console.app and Instruments.  On other platforms it falls back to
/// `print`.
public enum RNSLog {
#if canImport(os)
    private static let subsystem = "network.reticulum"
    private static let logger = Logger(subsystem: subsystem, category: "RNS")

    public static func debug(_ message: String) {
        logger.debug("\(message, privacy: .public)")
    }

    public static func info(_ message: String) {
        logger.info("\(message, privacy: .public)")
    }

    public static func error(_ message: String) {
        logger.error("\(message, privacy: .public)")
    }
#else
    public static func debug(_ message: String) { print("[RNS DEBUG] \(message)") }
    public static func info(_ message: String)  { print("[RNS INFO]  \(message)") }
    public static func error(_ message: String) { print("[RNS ERROR] \(message)") }
#endif
}

// MARK: - Data helpers

extension Data {
    /// Returns a lowercase hexadecimal string representation of the bytes.
    public func hexEncodedString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }

    /// Initialises `Data` from a hex-encoded string.
    ///
    /// Returns `nil` if `hexString` has an odd number of characters or contains
    /// non-hexadecimal digits.
    public init?(hexString: String) {
        let clean = hexString.lowercased()
        guard clean.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(clean.count / 2)
        var index = clean.startIndex
        while index < clean.endIndex {
            let next = clean.index(index, offsetBy: 2)
            guard let byte = UInt8(clean[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}
