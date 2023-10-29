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

import NIOCore
import NIOPosix
import NIOHTTP1
import Logging
import Dispatch
import NetworkExtension
import NIOSSL
import NIOHTTP2

//let bundleURL = Bundle.main.bundleURL
//print(bundleURL)
//do {
//  let currentFolderContents = try FileManager.default.contentsOfDirectory(at: bundleURL, includingPropertiesForKeys: nil)
//
//  print("Current app folder contents:")
//  for itemURL in currentFolderContents {
//    print(itemURL.lastPathComponent)
//  }
//} catch {
//  print("Error accessing current app folder: \(error)")
//}

//extension NIOSSLCertificate {
//  public convenience init(withOwnedReference ref: OpaquePointer) {
//    self._ref = ref
//  }
//}



let cert = "/Users/alex.vuong/Data/Learn/SwiftNIO/swift-nio-examples/connect-proxy/Sources/generated_cer.pem"
let privateKey = "/Users/alex.vuong/Data/Learn/SwiftNIO/swift-nio-examples/connect-proxy/Sources/generated_privatekey.pem"

let pkey = X509Certificate().generate_key2()
let x509 = X509Certificate().generate_x509(pkey: pkey)!

//var configuration = TLSConfiguration.makeServerConfiguration(
//  certificateChain: [.certificate(NIOSSLCertificate(withOwnedReference: x509))],
//  privateKey: .privateKey(NIOSSLPrivateKey(withReference: pkey.privateKey))
//)

var configuration = TLSConfiguration.makeServerConfiguration(
  certificateChain: try NIOSSLCertificate.fromPEMFile(cert).map { .certificate($0) },
  privateKey: .file(privateKey)
)
configuration.applicationProtocols =  ["http/1.1"] //NIOHTTP2SupportedALPNProtocols

let serverSSLContext = try NIOSSLContext(configuration: configuration)

var clientConfig = TLSConfiguration.makeClientConfiguration()
clientConfig.applicationProtocols =  ["http/1.1"] //NIOHTTP2SupportedALPNProtocols
clientConfig.certificateVerification = .noHostnameVerification
let clientSSLContext = try NIOSSLContext(configuration: clientConfig)

let group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
let bootstrap = ServerBootstrap(group: group)
  .childChannelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: 1)
  .serverChannelOption(ChannelOptions.socket(SOL_SOCKET, SO_REUSEADDR), value: 1)
  .childChannelOption(ChannelOptions.socket(SOL_SOCKET, SO_REUSEADDR), value: 1)
  .childChannelInitializer { channel in
      channel.pipeline.addHandler(ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes)))
          .flatMap { channel.pipeline.addHandler(HTTPResponseEncoder()) }
          .flatMap { channel.pipeline.addHandler(ConnectHandler(logger: Logger(label: "com.apple.nio-connect-proxy.ConnectHandler"))) }
  }


bootstrap.bind(to: try! SocketAddress(ipAddress: "127.0.0.1", port: 8080)).whenComplete { result in
  // Need to create this here for thread-safety purposes
  let logger = Logger(label: "com.apple.nio-connect-proxy.main")

  switch result {
  case .success(let channel):
    logger.info("Listening on \(String(describing: channel.localAddress))")
  case .failure(let error):
    logger.error("Failed to bind 127.0.0.1:8080, \(error)")
  }
}

// For IPV6
bootstrap.bind(to: try! SocketAddress(ipAddress: "::1", port: 8080)).whenComplete { result in
  // Need to create this here for thread-safety purposes
  let logger = Logger(label: "com.apple.nio-connect-proxy.main")

  switch result {
  case .success(let channel):
    logger.info("Listening on \(String(describing: channel.localAddress))")
  case .failure(let error):
    logger.error("Failed to bind [::1]:8080, \(error)")
  }
}


// Run forever
dispatchMain()

