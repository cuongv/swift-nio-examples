// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
  name: "http1-server",
  dependencies: [
    .package(url: "https://github.com/apple/swift-nio.git", from: "2.0.0"),
    .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.6.0"),
    .package(url: "https://github.com/apple/swift-nio-http2.git", from: "1.9.0"),
  ],
  targets: [
    // Targets are the basic building blocks of a package. A target can define a module or a test suite.
    // Targets can depend on other targets in this package, and on products in packages this package depends on.
    .executableTarget(
      name: "http1-server",
      dependencies: [
        .product(name: "NIO", package: "swift-nio"),
        .product(name: "NIOSSL", package: "swift-nio-ssl"),
        .product(name: "NIOHTTP1", package: "swift-nio"),
        .product(name: "NIOHTTP2", package: "swift-nio-http2"),

      ]),
    .testTarget(
      name: "http1-serverTests",
      dependencies: ["http1-server"]),
  ]
)
