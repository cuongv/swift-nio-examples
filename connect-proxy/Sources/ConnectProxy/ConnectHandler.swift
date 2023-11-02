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
import NIOHTTP2
import Logging
import NIOSSL
import NIOExtras

final class ConnectHandler {
  private var upgradeState: State
  private var logger: Logger
  public static var storedFrame = [HTTP2Frame]()
  public static var storedByteBuffer = [ByteBuffer]()
  private var host: String = ""

  init(logger: Logger) {
    self.upgradeState = .idle
    self.logger = logger
  }
}


extension ConnectHandler {
  fileprivate enum State {
    case idle
    case beganConnecting
    case awaitingEnd(connectResult: Channel)
    case awaitingConnection(pendingBytes: [NIOAny])
    case upgradeComplete(pendingBytes: [NIOAny])
    case upgradeFailed
  }
}


extension ConnectHandler: ChannelInboundHandler {
  typealias InboundIn = HTTPServerRequestPart
  typealias OutboundOut = HTTPServerResponsePart

  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    switch self.upgradeState {
    case .idle:
      self.handleInitialMessage(context: context, data: self.unwrapInboundIn(data))

    case .beganConnecting:
      // We got .end, we're still waiting on the connection
      if case .end = self.unwrapInboundIn(data) {
        self.upgradeState = .awaitingConnection(pendingBytes: [])
        self.removeDecoder(context: context)
      }

    case .awaitingEnd(let peerChannel):
      if case .end = self.unwrapInboundIn(data) {
        // Upgrade has completed!
        self.upgradeState = .upgradeComplete(pendingBytes: [])
        self.removeDecoder(context: context)
        self.glue(peerChannel, context: context)
      }

    case .awaitingConnection(var pendingBytes):
      // We've seen end, this must not be HTTP anymore. Danger, Will Robinson! Do not unwrap.
      self.upgradeState = .awaitingConnection(pendingBytes: [])
      pendingBytes.append(data)
      self.upgradeState = .awaitingConnection(pendingBytes: pendingBytes)

    case .upgradeComplete(pendingBytes: var pendingBytes):
      // We're currently delivering data, keep doing so.
      self.upgradeState = .upgradeComplete(pendingBytes: [])
      pendingBytes.append(data)
      self.upgradeState = .upgradeComplete(pendingBytes: pendingBytes)

    case .upgradeFailed:
      break
    }
  }

  func handlerAdded(context: ChannelHandlerContext) {
    // Add logger metadata.
    self.logger[metadataKey: "localAddress"] = "\(String(describing: context.channel.localAddress))"
    self.logger[metadataKey: "remoteAddress"] = "\(String(describing: context.channel.remoteAddress))"
    self.logger[metadataKey: "channel"] = "\(ObjectIdentifier(context.channel))"
  }
}


extension ConnectHandler: RemovableChannelHandler {
  func removeHandler(context: ChannelHandlerContext, removalToken: ChannelHandlerContext.RemovalToken) {
    var didRead = false

    // We are being removed, and need to deliver any pending bytes we may have if we're upgrading.
    while case .upgradeComplete(var pendingBytes) = self.upgradeState, pendingBytes.count > 0 {
      // Avoid a CoW while we pull some data out.
      self.upgradeState = .upgradeComplete(pendingBytes: [])
      let nextRead = pendingBytes.removeFirst()
      self.upgradeState = .upgradeComplete(pendingBytes: pendingBytes)

      context.fireChannelRead(nextRead)
      didRead = true
    }

    if didRead {
      context.fireChannelReadComplete()
    }

    self.logger.debug("Removing \(self) from pipeline")
    context.leavePipeline(removalToken: removalToken)
  }
}

extension ConnectHandler {
  private func handleInitialMessage(context: ChannelHandlerContext, data: InboundIn) {
    guard case .head(let head) = data else {
      self.logger.error("Invalid HTTP message type \(data)")
      self.httpErrorAndClose(context: context)
      return
    }

    self.logger.info("\(head.method) \(head.uri) \(head.version)")

    guard head.method == .CONNECT else {
      self.logger.error("Invalid HTTP method: \(head.method)")
      self.httpErrorAndClose(context: context)
      return
    }

    let components = head.uri.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
    let host = components.first!  // There will always be a first.
    let port = components.last.flatMap { Int($0, radix: 10) } ?? 80  // Port 80 if not specified

    self.host = String(host)
    print("host here: ", host)

    self.upgradeState = .beganConnecting
    self.connectTo(host: String(host), port: port, context: context)
  }

  private func connectTo(host: String, port: Int, context: ChannelHandlerContext) {
    self.logger.info("Connecting to \(host):\(port)")

    let channelFuture = ClientBootstrap(group: context.eventLoop)
      .connect(host: String(host), port: port)

    channelFuture.whenSuccess { channel in
      self.connectSucceeded(channel: channel, context: context)
    }
    channelFuture.whenFailure { error in
      self.connectFailed(error: error, context: context)
    }
  }

  private func connectSucceeded(channel: Channel, context: ChannelHandlerContext) {
    self.logger.info("Connected to \(String(describing: channel.remoteAddress))")

    switch self.upgradeState {
    case .beganConnecting:
      // Ok, we have a channel, let's wait for end.
      self.upgradeState = .awaitingEnd(connectResult: channel)

    case .awaitingConnection(pendingBytes: let pendingBytes):
      // Upgrade complete! Begin gluing the connection together.
      self.upgradeState = .upgradeComplete(pendingBytes: pendingBytes)
      self.glue(channel, context: context)

    case .awaitingEnd(let peerChannel):
      // This case is a logic error, close already connected peer channel.
      peerChannel.close(mode: .all, promise: nil)
      context.close(promise: nil)

    case .idle, .upgradeFailed, .upgradeComplete:
      // These cases are logic errors, but let's be careful and just shut the connection.
      context.close(promise: nil)
    }
  }

  private func connectFailed(error: Error, context: ChannelHandlerContext) {
    self.logger.error("Connect failed: \(error)")

    switch self.upgradeState {
    case .beganConnecting, .awaitingConnection:
      // We still have a somewhat active connection here in HTTP mode, and can report failure.
      self.httpErrorAndClose(context: context)

    case .awaitingEnd(let peerChannel):
      // This case is a logic error, close already connected peer channel.
      peerChannel.close(mode: .all, promise: nil)
      context.close(promise: nil)

    case .idle, .upgradeFailed, .upgradeComplete:
      // Most of these cases are logic errors, but let's be careful and just shut the connection.
      context.close(promise: nil)
    }

    context.fireErrorCaught(error)
  }

  private func glue(_ peerChannel: Channel, context: ChannelHandlerContext) {
    self.logger.debug("Gluing together \(ObjectIdentifier(context.channel)) and \(ObjectIdentifier(peerChannel))")

    // Ok, upgrade has completed! We now need to begin the upgrade process.
    // First, send the 200 message.
    // This content-length header is MUST NOT, but we need to workaround NIO's insistence that we set one.
    let headers = HTTPHeaders([("Content-Length", "0")])
    let head = HTTPResponseHead(version: .init(major: 1, minor: 1), status: .ok, headers: headers)
    context.write(self.wrapOutboundOut(.head(head)), promise: nil)
    context.writeAndFlush(self.wrapOutboundOut(.end(nil)), promise: nil)

    // Now remove the HTTP encoder.
    self.removeEncoder(context: context)
//    let debugInboundHandler = DebugInboundEventsHandler()
//    let debugOutboundHandler = DebugOutboundEventsHandler()
    // Now we need to glue our channel and the peer channel together.
    let (localGlue, peerGlue) = GlueHandler.matchedPair()

    var localHandlers = [ChannelHandler]()
    var peerHandlers = [ChannelHandler]()

    if "https://p.stg-myteksi.com".contains(host) {
//    if true {
      localHandlers = [
        NIOSSLServerHandler(context: getServerSSLContext()),
        SniperHandler(),
        //      NIOHTTP2Handler(mode: .server),
        //      HTTP2FrameHandler(),
        //      HTTP2FrameRevertHandler(),
        localGlue
      ]
      peerHandlers = [
        try! NIOSSLClientHandler(context: clientSSLContext, serverHostname: nil),
        peerGlue
      ]
    } else {
      localHandlers = [localGlue]
      peerHandlers = [peerGlue]
    }

    context.channel.pipeline.addHandlers(localHandlers).and(peerChannel.pipeline.addHandlers(peerHandlers))
    .whenComplete { result in
      switch result {
      case .success(_):
        context.pipeline.removeHandler(self, promise: nil)
        context.close(promise: nil)
//        print(context.pipeline)
//        print(peerChannel.pipeline)
      case .failure(_):
        // Close connected peer channel before closing our channel.
        peerChannel.close(mode: .all, promise: nil)
        context.close(promise: nil)
      }
    }
  }

  private func httpErrorAndClose(context: ChannelHandlerContext) {
    self.upgradeState = .upgradeFailed
    let headers = HTTPHeaders([("Content-Length", "0"), ("Connection", "close")])
    let head = HTTPResponseHead(version: .init(major: 1, minor: 1), status: .badRequest, headers: headers)
    context.write(self.wrapOutboundOut(.head(head)), promise: nil)
    context.writeAndFlush(self.wrapOutboundOut(.end(nil))).whenComplete { (_: Result<Void, Error>) in
      context.close(mode: .output, promise: nil)
    }
  }

  private func removeDecoder(context: ChannelHandlerContext) {
    // We drop the future on the floor here as these handlers must all be in our own pipeline, and this should
    // therefore succeed fast.
    context.pipeline.context(handlerType: ByteToMessageHandler<HTTPRequestDecoder>.self).whenSuccess {
      context.pipeline.removeHandler(context: $0, promise: nil)
    }
  }

  private func removeEncoder(context: ChannelHandlerContext) {
    context.pipeline.context(handlerType: HTTPResponseEncoder.self).whenSuccess {
      context.pipeline.removeHandler(context: $0, promise: nil)
    }
  }

  private func getServerSSLContext() -> NIOSSLContext {
    let cert = "/Users/alex.vuong/Data/Learn/SwiftNIO/swift-nio-examples/connect-proxy/Sources/generated_cer.pem"
    let privateKey = "/Users/alex.vuong/Data/Learn/SwiftNIO/swift-nio-examples/connect-proxy/Sources/generated_privatekey.pem"

    let pkey = X509Certificate().generate_key2()
    let x509 = X509Certificate().generate_x509(pkey: pkey.1, host: host, isCA: false)!

//    var configuration = TLSConfiguration.makeServerConfiguration(
//      certificateChain: [.certificate(NIOSSLCertificate(withOwnedReference: x509))],
//      privateKey: .privateKey(NIOSSLPrivateKey(withReference: pkey.0))
//    )

    var configuration = TLSConfiguration.makeServerConfiguration(
      certificateChain: try! NIOSSLCertificate.fromPEMFile(cert).map { .certificate($0) },
      privateKey: .file(privateKey)
    )
    configuration.applicationProtocols =  ["http/1.1"] //NIOHTTP2SupportedALPNProtocols

    let serverSSLContext = try! NIOSSLContext(configuration: configuration)
    return serverSSLContext
  }
}

final class ByteBuffStorage: ChannelInboundHandler {
  public typealias InboundIn = ByteBuffer
  public typealias InboundOut = ByteBuffer

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    print("Call: ByteBuffStorage")
    let bytebuff = self.unwrapInboundIn(data)
    ConnectHandler.storedByteBuffer.append(bytebuff)
    context.fireChannelRead(self.wrapInboundOut(bytebuff))
  }
}

final class SniperHandler: ChannelInboundHandler & ChannelOutboundHandler {
  typealias OutboundIn = ByteBuffer

  public typealias InboundIn = ByteBuffer
  public typealias InboundOut = ByteBuffer

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let inBuff = self.unwrapInboundIn(data)
    let str = inBuff.getString(at: 0, length: inBuff.readableBytes)
    print("Get data in sniff: ", str!)
    context.fireChannelRead(self.wrapInboundOut(inBuff))
  }
}

func convertRequestPartToByteBuffer(_ part: HTTPServerRequestPart) -> ByteBuffer? {
  var buffer = ByteBufferAllocator().buffer(capacity: 0) // Create an empty buffer

  switch part {
  case .head(let requestHead):
    // Serialize the request head and append it to the buffer
    buffer.writeString("\(requestHead.method) \(requestHead.uri)\r\n")
    for (name, value) in requestHead.headers {
      buffer.writeString("\(name): \(value)\r\n")
    }
    buffer.writeString("\r\n") // End of headers

  case .body(var bodyBuffer):
    // Append the body buffer to the main buffer
    buffer.writeBuffer(&bodyBuffer)

  case .end:
    // No specific action needed for the end of the request
    break
  }

  return buffer
}

final class ErrorHandler: ChannelInboundHandler, Sendable {
  typealias InboundIn = Never

  func errorCaught(context: ChannelHandlerContext, error: Error) {
    print("Server received error: \(error)")
    context.close(promise: nil)
  }
}

