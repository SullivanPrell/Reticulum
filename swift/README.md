# Reticulum Swift

A native Swift implementation of the [Reticulum](https://reticulum.network) network
stack, targeting **iOS 14+**, **iPadOS 14+**, and **macOS 11+**.

## Overview

This Swift package provides the core Reticulum primitives as a Swift library that
can be embedded directly in iOS, iPadOS, and macOS apps — no Python runtime required.

| Component | Description |
|-----------|-------------|
| `Identity` | X25519 ECDH encryption + Ed25519 signing, iOS Keychain persistence |
| `Destination` | Endpoint addressing with deterministic hash derivation |
| `Packet` | Binary wire-format encoding / decoding |
| `Transport` | Routing, duplicate detection, announce handling, forwarding |
| `Link` | Encrypted, forward-secret peer-to-peer links |
| `TCPClientInterface` | TCP client using `Network.framework` |
| `UDPInterface` | UDP transceiver using `Network.framework` |

## Requirements

- Swift 5.9+
- iOS 14+ / iPadOS 14+ / macOS 11+

## Installation

### Swift Package Manager

Add the package to your `Package.swift` or in Xcode via
**File → Add Package Dependencies**:

```swift
dependencies: [
    .package(url: "https://github.com/SullivanPrell/Reticulum", branch: "swift"),
],
targets: [
    .target(name: "MyApp", dependencies: [
        .product(name: "Reticulum", package: "Reticulum"),
    ]),
],
```

## Quick start

```swift
import Reticulum

// 1. Create the stack
let rns = Reticulum()

// 2. Add an interface
let iface = TCPClientInterface(name: "MyTCP", host: "example.com", port: 4242)
rns.addInterface(iface)

// 3. Create a local identity and destination
let identity = Identity()
let destination = Destination(
    identity: identity,
    direction: .in,
    type: .single,
    appName: "com.example.myapp",
    aspects: ["echo"]
)
destination.packetCallback = { packet, data in
    print("Received: \(String(data: data, encoding: .utf8) ?? "<binary>")")
}
rns.registerDestination(destination)

// 4. Start
try rns.start()

// 5. Announce presence on the network
try rns.announce(destination: destination)

// 6. Send data
rns.send(data: Data("Hello!".utf8), to: destination)
```

## Key persistence (Keychain)

```swift
// Save
try identity.saveToKeychain(account: "my-reticulum-identity")

// Load
if let loaded = try Identity.loadFromKeychain(account: "my-reticulum-identity") {
    // use loaded identity
}
```

## Building & Testing

```bash
cd swift
swift build
swift test
```

## Architecture

```
Reticulum (entry point)
    └── Transport  ──────────── packet routing, announce handling
          ├── TCPClientInterface   (Network.framework)
          └── UDPInterface         (Network.framework)

Identity    ──  X25519 + Ed25519 key pairs (Crypto / CryptoKit)
Destination ──  addressable endpoint, hash derivation
Packet      ──  binary wire-format encode / decode
Link        ──  ephemeral ECDH session, forward secrecy
```

## License

Reticulum License — Copyright (c) 2016-2025 Mark Qvist.  
See [LICENSE](../LICENSE) for full terms.
