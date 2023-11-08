//
//  File.swift
//  
//
//  Created by Alex Vuong on 8/11/23.
//

import NIO
import NIOSSL
import NIOTLS

final class HeuristicForServerTooOldToSpeakGoodProtocolsHandler: ChannelInboundHandler {
  typealias InboundIn = ByteBuffer
  typealias InboundOut = ByteBuffer

  enum Error: Swift.Error {
    case serverDoesNotSpeakHTTP2
  }

  var bytesSeen = 0

  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let buffer = self.unwrapInboundIn(data)
    bytesSeen += buffer.readableBytes
    context.fireChannelRead(data)
  }

  func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
    print("userInboundEventTriggered: ", event)
    if self.bytesSeen == 0 {
      if case let event = event as? TLSUserEvent, event == .shutdownCompleted || event == .handshakeCompleted(negotiatedProtocol: nil) {
        print("Server is using http1.1")
//        context.fireErrorCaught(Error.serverDoesNotSpeakHTTP2)
        return
      }
    }
    print("Server is using http2.0")
    context.fireUserInboundEventTriggered(event)
  }

  func errorCaught(context: ChannelHandlerContext, error: Swift.Error) {
    if self.bytesSeen == 0 {
      switch error {
      case NIOSSLError.uncleanShutdown,
        is IOError where (error as! IOError).errnoCode == ECONNRESET:
        // this is very highly likely a server doesn't speak HTTP/2 problem
        print("Server is using http1.1")
//        context.fireErrorCaught(Error.serverDoesNotSpeakHTTP2)
        return
      default:
        ()
      }
    }
    context.fireErrorCaught(error)
  }
}
