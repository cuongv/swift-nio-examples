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
import NIOSSL
import NIOHTTP1
import NIOHTTP2

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
        buffer.writeBuffer(&bodyBuffer)

    case .end:
        // No specific action needed for the end of the request
        break
    }

    return buffer
}

final class HTTP1TestServer: ChannelInboundHandler {
  public typealias InboundIn = HTTPServerRequestPart
//  public typealias InboundOut = ByteBuffer
  public typealias OutboundOut = HTTPServerResponsePart

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let reqPart = self.unwrapInboundIn(data)
    switch reqPart {
    case .head(let request):
      print("request: ", request)
//        if request.uri.unicodeScalars.starts(with: "/dynamic".unicodeScalars) {
//            self.handler = self.dynamicHandler(request: request)
//            self.handler!(context, reqPart)
//            return
//        } else if let path = request.uri.chopPrefix("/sendfile/") {
//            self.handler = { self.handleFile(context: $0, request: $1, ioMethod: .sendfile, path: path) }
//            self.handler!(context, reqPart)
//            return
//        } else if let path = request.uri.chopPrefix("/fileio/") {
//            self.handler = { self.handleFile(context: $0, request: $1, ioMethod: .nonblockingFileIO, path: path) }
//            self.handler!(context, reqPart)
//            return
//        }
//
//        self.keepAlive = request.isKeepAlive
//        self.state.requestReceived()
//
//        var responseHead = httpResponseHead(request: request, status: HTTPResponseStatus.ok)
//        self.buffer.clear()
//        self.buffer.writeString(self.defaultResponse)
//        responseHead.headers.add(name: "content-length", value: "\(self.buffer!.readableBytes)")
//        let response = HTTPServerResponsePart.head(responseHead)
//        context.write(self.wrapOutboundOut(response), promise: nil)
    case .body(let body):
      let str = body.getString(at: 0, length: body.readableBytes)
      print("Case body: ", str!)
        break
    case .end:
      print("Case end")
//        self.state.requestComplete()
//        let content = HTTPServerResponsePart.body(.byteBuffer(buffer!.slice()))
//        context.write(self.wrapOutboundOut(content), promise: nil)
//        self.completeResponse(context, trailers: nil, promise: nil)
    }

//    return context.fireChannelRead(self.wrapInboundOut(convertRequestPartToByteBuffer(reqPart)!))

    guard case .end = self.unwrapInboundIn(data) else {
      return
    }

    // Insert an event loop tick here. This more accurately represents real workloads in SwiftNIO, which will not
    // re-entrantly write their response frames.
    print(context.pipeline)
    context.eventLoop.execute {
      context.channel.getOption(HTTP2StreamChannelOptions.streamID).flatMap { (streamID) -> EventLoopFuture<Void> in
        print("Get request from client")
        let str = "Hello Nu"
        var headers = HTTPHeaders()
        headers.add(name: "content-length", value: "\(str.count)")
        headers.add(name: "x-stream-id", value: String(Int(streamID)))
        context.channel.write(self.wrapOutboundOut(HTTPServerResponsePart.head(HTTPResponseHead(version: .init(major: 2, minor: 0), status: .ok, headers: headers))), promise: nil)

        var buffer = context.channel.allocator.buffer(capacity: 12)
        buffer.writeString(str)
        context.channel.write(self.wrapOutboundOut(HTTPServerResponsePart.body(.byteBuffer(buffer))), promise: nil)
        return context.channel.writeAndFlush(self.wrapOutboundOut(HTTPServerResponsePart.end(nil)))
      }.whenComplete { _ in
        context.close(promise: nil)
      }
    }
  }
}


final class ErrorHandler: ChannelInboundHandler, Sendable {
  typealias InboundIn = Never

  func errorCaught(context: ChannelHandlerContext, error: Error) {
    print("Server received error: \(error)")
    context.close(promise: nil)
  }
}

// First argument is the program path
let arguments = CommandLine.arguments
let arg1 = arguments.dropFirst().first
let arg2 = arguments.dropFirst().dropFirst().first
let arg3 = arguments.dropFirst().dropFirst().dropFirst().first

let defaultHost = "127.0.0.1"
let defaultPort: Int = 9090
let defaultHtdocs = "/dev/null/"

enum BindTo {
  case ip(host: String, port: Int)
  case unixDomainSocket(path: String)
}

let htdocs: String
let bindTarget: BindTo
switch (arg1, arg1.flatMap { Int($0) }, arg2, arg2.flatMap { Int($0) }, arg3) {
case (.some(let h), _ , _, .some(let p), let maybeHtdocs):
  /* second arg an integer --> host port [htdocs] */
  bindTarget = .ip(host: h, port: p)
  htdocs = maybeHtdocs ?? defaultHtdocs
case (_, .some(let p), let maybeHtdocs, _, _):
  /* first arg an integer --> port [htdocs] */
  bindTarget = .ip(host: defaultHost, port: p)
  htdocs = maybeHtdocs ?? defaultHtdocs
case (.some(let portString), .none, let maybeHtdocs, .none, .none):
  /* couldn't parse as number --> uds-path [htdocs] */
  bindTarget = .unixDomainSocket(path: portString)
  htdocs = maybeHtdocs ?? defaultHtdocs
default:
  htdocs = defaultHtdocs
  bindTarget = BindTo.ip(host: defaultHost, port: defaultPort)
}

// The following lines load the example private key/cert from HardcodedPrivateKeyAndCerts.swift .
// DO NOT USE THESE KEYS/CERTIFICATES IN PRODUCTION.
// For a real server, you would obtain a real key/cert and probably put them in files and load them with
//
//     NIOSSLPrivateKeySource.file("/path/to/private.key")
//     NIOSSLCertificateSource.file("/path/to/my.cert")

// Load the private key
let sslPrivateKey = try! NIOSSLPrivateKeySource.privateKey(NIOSSLPrivateKey(bytes: Array(samplePKCS8PemPrivateKey.utf8),
                                                                            format: .pem) { providePassword in
  providePassword("thisisagreatpassword".utf8)
})

// Load the certificate
let sslCertificate = try! NIOSSLCertificateSource.certificate(NIOSSLCertificate(bytes: Array(samplePemCert.utf8),
                                                                                format: .pem))

// Set up the TLS configuration, it's important to set the `applicationProtocols` to
// `NIOHTTP2SupportedALPNProtocols` which (using ALPN (https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation))
// advertises the support of HTTP/2 to the client.
//var serverConfig = TLSConfiguration.makeServerConfiguration(certificateChain: [sslCertificate], privateKey: sslPrivateKey)

let cert = "/users/alex.vuong/data/learn/swiftnio/swift-nio-examples/connect-proxy/sources/localhost_cer.pem"
let privateKey = "/users/alex.vuong/data/learn/swiftnio/swift-nio-examples/connect-proxy/sources/localhost_key.pem"

var serverConfig = TLSConfiguration.makeServerConfiguration(
  certificateChain: try NIOSSLCertificate.fromPEMFile(cert).map { .certificate($0) },
  privateKey: .file(privateKey)
)
serverConfig.applicationProtocols = NIOHTTP2SupportedALPNProtocols
// Configure the SSL context that is used by all SSL handlers.
let sslContext = try! NIOSSLContext(configuration: serverConfig)

let group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
let bootstrap = ServerBootstrap(group: group)
// Specify backlog and enable SO_REUSEADDR for the server itself
  .serverChannelOption(ChannelOptions.backlog, value: 256)
  .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)

// Set the handlers that are applied to the accepted Channels
  .childChannelInitializer { channel in
    // First, we need an SSL handler because HTTP/2 is almost always spoken over TLS.
    channel.pipeline.addHandlers([
      NIOSSLServerHandler(context: sslContext),
//      SniperHandler()
    ]).flatMap {
      // Right after the SSL handler, we can configure the HTTP/2 pipeline.
      channel.configureHTTP2Pipeline(mode: .server) { (streamChannel) -> EventLoopFuture<Void> in
        // For every HTTP/2 stream that the client opens, we put in the `HTTP2ToHTTP1ServerCodec` which
        // transforms the HTTP/2 frames to the HTTP/1 messages from the `NIOHTTP1` module.
        streamChannel.pipeline.addHandler(HTTP2FramePayloadToHTTP1ServerCodec()).flatMap { () -> EventLoopFuture<Void> in
          // And lastly, we put in our very basic HTTP server :).
          print("Pipeline: ", streamChannel.pipeline)
          return streamChannel.pipeline.addHandler(HTTP1TestServer())
        }.flatMap { () -> EventLoopFuture<Void> in
          streamChannel.pipeline.addHandler(ErrorHandler())
        }
      }
    }.flatMap { (_: HTTP2StreamMultiplexer) in
      return channel.pipeline.addHandler(ErrorHandler())
    }
  }

// Enable TCP_NODELAY and SO_REUSEADDR for the accepted Channels
  .childChannelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: 1)
  .childChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
  .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 1)

defer {
  try! group.syncShutdownGracefully()
}

print("htdocs = \(htdocs)")

let channel = try { () -> Channel in
  switch bindTarget {
  case .ip(let host, let port):
    return try bootstrap.bind(host: host, port: port).wait()
  case .unixDomainSocket(let path):
    return try bootstrap.bind(unixDomainSocketPath: path).wait()
  }
}()

print("Server started and listening on \(channel.localAddress!), htdocs path \(htdocs)")
print("\nTry it out by running")
print("    # WARNING: We're passing --insecure here because we don't have a real cert/private key!")
print("    # In production NEVER use --insecure.")
switch bindTarget {
case .ip(let host, let port):
  let hostFormatted: String
  switch channel.localAddress!.protocol {
  case .inet6:
    hostFormatted = host.contains(":") ? "[\(host)]" : host
  default:
    hostFormatted = "\(host)"
  }
  print("    curl --insecure https://\(hostFormatted):\(port)/hello-world")
case .unixDomainSocket(let path):
  print("    curl --insecure --unix-socket '\(path)' https://ignore-the-server.name/hello-world")
}


// This will never unblock as we don't close the ServerChannel
try channel.closeFuture.wait()

print("Server closed")

final class SniperHandler: ChannelInboundHandler {
  public typealias InboundIn = ByteBuffer
  public typealias InboundOut = ByteBuffer

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let inBuff = self.unwrapInboundIn(data)
    let str = inBuff.getString(at: 0, length: inBuff.readableBytes)
    print("Get data in sniff: ", str!)
    context.fireChannelRead(self.wrapInboundOut(inBuff))


//    context.channel.configureHTTP2Pipeline(mode: .server) { (streamChannel) -> EventLoopFuture<Void> in
//      // For every HTTP/2 stream that the client opens, we put in the `HTTP2ToHTTP1ServerCodec` which
//      // transforms the HTTP/2 frames to the HTTP/1 messages from the `NIOHTTP1` module.
//      streamChannel.pipeline.addHandler(HTTP2FramePayloadToHTTP1ServerCodec()).flatMap { () -> EventLoopFuture<Void> in
//        // And lastly, we put in our very basic HTTP server :).
//        streamChannel.pipeline.addHandler(HTTP1TestServer())
//      }
//    }
//    .whenComplete { result in
//      print("completed")
//      switch result {
//      case .success(_):
//        context.close(promise: nil)
//      case .failure(_):
//        // Close connected peer channel before closing our channel.
//        context.close(promise: nil)
//      }
//    }
  }
}
