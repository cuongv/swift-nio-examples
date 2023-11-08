//
//  File.swift
//  
//
//  Created by Alex Vuong on 8/11/23.
//

import Foundation
import NIO
import NIOSSL

class ClientTest {
  func test() {
    let group2 = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    defer {
      try! group2.syncShutdownGracefully()
    }

    var tlsConfiguration = TLSConfiguration.makeClientConfiguration()
    tlsConfiguration.applicationProtocols = ["h2", "http/1.1"]
    let sslContext = try! NIOSSLContext(configuration: tlsConfiguration)

    let handler = HTTPResponseHandler()
    let sslHandler = try! NIOSSLClientHandler(context: sslContext, serverHostname: nil)
    let bootstrap = ClientBootstrap(group: group2)
    // Enable TLS for the connection.
      .channelInitializer { channel in

        return channel.pipeline.addHandlers([sslHandler, HTTPVersionDetectorHandler()])
//          .flatMap {
//          channel.pipeline.addHTTPClientHandlers()
//        }.flatMap {
//          channel.pipeline.addHandler(handler)
//        }
      }
    // Enable verbose logging for everything.
      .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)

    //p.stg-myteksi.com
    bootstrap.connect(host: "p.stg-myteksi.com", port: 443).whenSuccess { channel in
//      DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
        print(sslHandler.connection.getAlpnProtocol())
//      }
    }

    // Send an HTTP request.
//    var buffer = channel.allocator.buffer(capacity: 0)
//    buffer.writeString("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
//    try? channel.writeAndFlush(buffer).wait()
//

    // Wait until the channel is closed.
//    try? channel.closeFuture.wait()
  }
}
class HTTPResponseHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let byteBuffer = unwrapInboundIn(data)

        if let string = byteBuffer.getString(at: 0, length: byteBuffer.readableBytes) {
            print("Response from server:\n\(string)")
        }

        // Once we get a response, we close the connection.
        context.close(promise: nil)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        print("Error: \(error)")
        context.close(promise: nil)
    }
}
