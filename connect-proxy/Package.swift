// swift-tools-version:5.6
//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import PackageDescription

let package = Package(
    name: "nio-connect-proxy",
    platforms: [
      .macOS(.v10_15)  // Set the minimum macOS version
    ],
    products: [
        .executable(name: "ConnectProxy", targets: ["ConnectProxy"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.42.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
//        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.23.2"),
        .package(path: "/Users/alex.vuong/Data/Learn/SwiftNIO/swift-nio-examples/local-swift-nio-ssl/swift-nio-ssl/"),
        .package(url: "https://github.com/apple/swift-nio-http2.git", from: "1.9.0"),
        .package(url: "https://github.com/apple/swift-nio-extras.git", from: "1.0.0"),
        .package(url: "https://github.com/krzyzanowskim/OpenSSL.git", .upToNextMinor(from: "3.1.3000")),
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "2.0.0")),
    ],
    targets: [
        .executableTarget(
            name: "ConnectProxy",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "NIOHTTP2", package: "swift-nio-http2"),
                .product(name: "NIOExtras", package: "swift-nio-extras"),
                .product(name: "OpenSSL", package: "OpenSSL"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]),
    ]
)
