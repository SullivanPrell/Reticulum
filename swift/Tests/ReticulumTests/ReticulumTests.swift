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

import XCTest
@testable import Reticulum

final class IdentityTests: XCTestCase {

    // MARK: - Key Generation

    func testKeyGeneration() {
        let identity = Identity()
        XCTAssertEqual(identity.publicKey.count, 64, "Public key should be 64 bytes")
        XCTAssertTrue(identity.hasPrivateKey, "Newly created identity should have private keys")
    }

    func testPrivateKeyRoundTrip() throws {
        let original  = Identity()
        let privBytes = try original.privateKey()
        XCTAssertEqual(privBytes.count, 64)

        let restored  = try Identity(privateKeyData: privBytes)
        XCTAssertEqual(original.publicKey, restored.publicKey)
        XCTAssertEqual(original.hash, restored.hash)
    }

    func testPublicKeyOnlyIdentity() throws {
        let full     = Identity()
        let pubOnly  = try Identity(publicKeyData: full.publicKey)
        XCTAssertFalse(pubOnly.hasPrivateKey)
        XCTAssertEqual(full.publicKey, pubOnly.publicKey)
        XCTAssertEqual(full.hash, pubOnly.hash)
    }

    // MARK: - Hashing

    func testTruncatedHashLength() {
        let identity = Identity()
        XCTAssertEqual(identity.truncatedHash.count, 16, "Truncated hash should be 16 bytes (128 bits)")
    }

    func testHexHashLength() {
        let identity = Identity()
        XCTAssertEqual(identity.hexHash.count, 32, "Hex-encoded 16-byte hash should be 32 characters")
    }

    // MARK: - Signing

    func testSignAndVerify() throws {
        let identity  = Identity()
        let message   = Data("Hello, Reticulum!".utf8)
        let signature = try identity.sign(message: message)
        XCTAssertEqual(signature.count, 64, "Ed25519 signature should be 64 bytes")
        XCTAssertTrue(identity.validate(signature: signature, for: message))
    }

    func testSignatureRejectedForTamperedMessage() throws {
        let identity  = Identity()
        let message   = Data("Hello, Reticulum!".utf8)
        let signature = try identity.sign(message: message)
        let tampered  = Data("Hello, Reticulum?".utf8)
        XCTAssertFalse(identity.validate(signature: signature, for: tampered))
    }

    func testSigningRequiresPrivateKey() throws {
        let full     = Identity()
        let pubOnly  = try Identity(publicKeyData: full.publicKey)
        XCTAssertThrowsError(try pubOnly.sign(message: Data("test".utf8)))
    }

    // MARK: - Encryption / Decryption

    func testEncryptDecryptRoundTrip() throws {
        let identity  = Identity()
        let plaintext = Data("Secret message 42".utf8)
        let token     = try identity.encrypt(plaintext: plaintext)
        let recovered = try identity.decrypt(token: token)
        XCTAssertEqual(recovered, plaintext)
    }

    func testDecryptWithWrongKey() throws {
        let alice     = Identity()
        let bob       = Identity()
        let plaintext = Data("Alice's secret".utf8)
        let token     = try alice.encrypt(plaintext: plaintext)
        // Bob's key can't decrypt a message encrypted for Alice
        let result    = try? bob.decrypt(token: token)
        XCTAssertNil(result, "Decryption with wrong key should fail")
    }

    // MARK: - Known Destinations Registry

    func testRememberAndRecall() {
        let identity = Identity()
        let hash     = identity.truncatedHash
        Identity.remember(identity: identity, destinationHash: hash)
        let recalled = Identity.recall(destinationHash: hash)
        XCTAssertNotNil(recalled)
        XCTAssertEqual(recalled?.publicKey, identity.publicKey)
        Identity.forgetAll()
    }
}

final class DestinationTests: XCTestCase {

    func testHashIsDeterministic() {
        let id = Identity()
        let d1 = Destination(identity: id, direction: .in, type: .single, appName: "app", aspects: ["test"])
        let d2 = Destination(identity: id, direction: .in, type: .single, appName: "app", aspects: ["test"])
        XCTAssertEqual(d1.hash, d2.hash)
    }

    func testHashLength() {
        let id   = Identity()
        let dest = Destination(identity: id, direction: .in, type: .single, appName: "app", aspects: ["echo"])
        XCTAssertEqual(dest.hash.count, 16, "Destination hash should be 16 bytes")
    }

    func testFullName() {
        let id   = Identity()
        let dest = Destination(identity: id, direction: .in, type: .single, appName: "myapp", aspects: ["service", "v1"])
        XCTAssertEqual(dest.fullName, "myapp.service.v1")
    }

    func testNameHashLength() {
        let id   = Identity()
        let dest = Destination(identity: id, direction: .in, type: .single, appName: "app", aspects: [])
        XCTAssertEqual(dest.nameHash.count, 10, "Name hash should be 10 bytes (80 bits)")
    }

    func testBuildAnnouncePayload() throws {
        let id   = Identity()
        let dest = Destination(identity: id, direction: .in, type: .single, appName: "app", aspects: ["announce"])
        let payload = try dest.buildAnnouncePayload()
        // Minimum: 16 + 64 + 10 + 64 = 154 bytes
        XCTAssertNotNil(payload)
        XCTAssertGreaterThanOrEqual(payload!.count, 154)
    }
}

final class PacketTests: XCTestCase {

    func testEncodeDecodeRoundTrip() {
        let destHash = Data(repeating: 0xAB, count: 16)
        let payload  = Data("test payload".utf8)
        let packet   = Packet(destinationHash: destHash, data: payload)
        let bytes    = packet.toBytes()
        let decoded  = Packet.fromBytes(bytes)
        XCTAssertNotNil(decoded)
        XCTAssertEqual(decoded?.destinationHash, destHash)
        XCTAssertEqual(decoded?.data, payload)
        XCTAssertEqual(decoded?.packetType, .data)
        XCTAssertEqual(decoded?.hopCount, 0)
    }

    func testHeader2RoundTrip() {
        let destHash    = Data(repeating: 0x01, count: 16)
        let transportID = Data(repeating: 0x02, count: 16)
        let payload     = Data("forwarded".utf8)
        let packet = Packet(
            destinationHash: destHash,
            data: payload,
            packetType: .data,
            context: .none,
            transportType: .transport,
            headerType: .header2,
            destinationType: .single,
            transportID: transportID,
            hopCount: 3
        )
        let bytes   = packet.toBytes()
        let decoded = Packet.fromBytes(bytes)
        XCTAssertNotNil(decoded)
        XCTAssertEqual(decoded?.headerType, .header2)
        XCTAssertEqual(decoded?.transportType, .transport)
        XCTAssertEqual(decoded?.hopCount, 3)
        XCTAssertEqual(decoded?.transportID, transportID)
    }

    func testPacketHashIsDeterministic() {
        let destHash = Data(repeating: 0xCC, count: 16)
        let packet1  = Packet(destinationHash: destHash, data: Data("hello".utf8))
        let packet2  = Packet(destinationHash: destHash, data: Data("hello".utf8))
        XCTAssertEqual(packet1.packetHash, packet2.packetHash)
    }

    func testTooShortPacketReturnsNil() {
        XCTAssertNil(Packet.fromBytes(Data([0x00, 0x00])))
    }

    func testAnnouncePakcetType() {
        let destHash = Data(repeating: 0x11, count: 16)
        let packet   = Packet(destinationHash: destHash, data: Data(), packetType: .announce)
        let bytes    = packet.toBytes()
        let decoded  = Packet.fromBytes(bytes)
        XCTAssertEqual(decoded?.packetType, .announce)
    }
}

final class TransportTests: XCTestCase {

    func testDuplicatePacketDropped() {
        let transport = Transport()
        let mock      = MockInterface(name: "mock")
        transport.addInterface(mock)

        let id      = Identity()
        let dest    = Destination(identity: id, direction: .in, type: .single, appName: "app", aspects: ["dup"])
        transport.registerDestination(dest)

        var callCount = 0
        dest.packetCallback = { _, _ in callCount += 1 }

        let packet = Packet(destinationHash: dest.hash, data: Data("hi".utf8))
        let bytes  = packet.toBytes()

        transport.inbound(data: bytes, interface: mock)
        transport.inbound(data: bytes, interface: mock)

        // Only the first packet should be dispatched; the duplicate must be dropped.
        XCTAssertEqual(callCount, 1, "Duplicate packet should be dropped by transport")
    }

    func testRegisterAndDispatchToDestination() {
        let transport = Transport()
        let mock      = MockInterface(name: "mock")
        transport.addInterface(mock)

        let id      = Identity()
        let dest    = Destination(identity: id, direction: .in, type: .single, appName: "app", aspects: ["test"])
        transport.registerDestination(dest)

        var receivedData: Data?
        dest.packetCallback = { _, data in receivedData = data }

        let payload  = Data("payload".utf8)
        let packet   = Packet(destinationHash: dest.hash, data: payload)
        transport.inbound(data: packet.toBytes(), interface: mock)

        XCTAssertEqual(receivedData, payload)
    }
}

// MARK: - Test Helpers

final class MockInterface: RNSInterface {
    let name: String
    var `in`:  Bool = true
    var `out`: Bool = true
    var fwd:   Bool = false
    var mode: InterfaceMode = .full
    var rxb: UInt64 = 0
    var txb: UInt64 = 0
    weak var transport: Transport?

    init(name: String) { self.name = name }

    func processOutbound(_ data: Data) { txb += UInt64(data.count) }
    func start() throws {}
    func stop() {}
}

final class DataUtilityTests: XCTestCase {

    func testHexEncoding() {
        let data = Data([0xDE, 0xAD, 0xBE, 0xEF])
        XCTAssertEqual(data.hexEncodedString(), "deadbeef")
    }

    func testHexDecoding() {
        let data = Data(hexString: "deadbeef")
        XCTAssertEqual(data, Data([0xDE, 0xAD, 0xBE, 0xEF]))
    }

    func testHexDecodingInvalidInput() {
        XCTAssertNil(Data(hexString: "XYZ"))
        XCTAssertNil(Data(hexString: "ABC"))   // odd number of chars
    }
}
