//
//  File.swift
//  
//
//  Created by Alex Vuong on 26/10/23.
//

import NIO
import NIOHTTP1
import NIOSSL
import NIOTLS

final class HTTP1Handler: ChannelInboundHandler {
  typealias InboundIn = HTTPServerRequestPart
  typealias OutboundOut = HTTPServerResponsePart

  public func channelActive(context: ChannelHandlerContext) {
    print("Channel active")
//    context.pipeline.context(handlerType: NIOSSLServerHandler.self).whenSuccess {
//      context.pipeline.removeHandler(context: $0, promise: nil)
//    }
  }

  func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
    print("userInboundEventTriggered: ", event)
//    if let event = event as? TLSUserEvent, case .handshakeCompleted(let negotiatedProtocol) = event {
//
//    }
    context.fireUserInboundEventTriggered(event)
  }

  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let requestPart = self.unwrapInboundIn(data)
    let str = "Hello Nu"
    print("Channel read")
    switch requestPart {
    case .head(let headerFromRequest):
      var headers = HTTPHeaders()
      headers.add(name: "content-length", value: "\(str.count)")
      let responseHead = HTTPResponseHead(version: headerFromRequest.version, status: .ok, headers: headers)
      context.write(self.wrapOutboundOut(.head(responseHead)), promise: nil)
      print("Header of request")
      print(headerFromRequest)
    case .body(let bodyFromRequest):
      if let str = bodyFromRequest.getString(at: 0, length: bodyFromRequest.readableBytes) {
        print("Body of request: ")
        print(str)
      }
//      context.write(self.wrapOutboundOut(.body(.byteBuffer(body))), promise: nil)
      break
    case .end:
      var buffer = context.channel.allocator.buffer(capacity: str.count)
      buffer.writeString(str)
      context.write(self.wrapOutboundOut(HTTPServerResponsePart.body(.byteBuffer(buffer))), promise: nil)

      context.writeAndFlush(self.wrapOutboundOut(.end(nil))).whenComplete { result in
        print("Finish write and flush")
        context.close(promise: nil)
      }

//      context.eventLoop.execute {
//        print("Get request from client")
//        let str = "Hello Nu"
//        var headers = HTTPHeaders()
//        headers.add(name: "content-length", value: "\(str.count)")
////        headers.add(name: "x-stream-id", value: String(Int(streamID)))
//        context.channel.write(self.wrapOutboundOut(HTTPServerResponsePart.head(HTTPResponseHead(version: .init(major: 1, minor: 1), status: .ok, headers: headers))), promise: nil)
//
//        var buffer = context.channel.allocator.buffer(capacity: 12)
//        buffer.writeString(str)
//        context.channel.write(self.wrapOutboundOut(HTTPServerResponsePart.body(.byteBuffer(buffer))), promise: nil)
//        context.channel.writeAndFlush(self.wrapOutboundOut(HTTPServerResponsePart.end(nil)))
//      }

    }
  }

  func channelReadComplete(context: ChannelHandlerContext) {
    print("Channel read complete")
  }
}
