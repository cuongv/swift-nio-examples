//
//  File.swift
//  
//
//  Created by Alex Vuong on 24/8/23.
//

import NIOCore
import NIOPosix
import NIOHTTP1
import NIOHTTP2
import Logging
import NIOSSL
import NIOExtras


final class HTTP2FrameHandler:  ChannelInboundHandler {
  public typealias InboundIn = HTTP2Frame
  public typealias InboundOut = ByteBuffer

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    print("Call: HTTP2FrameHandler channelRead")
    let frame = self.unwrapInboundIn(data)
    ConnectHandler.storedFrame.append(frame)
    switch frame.payload {
    case .data(let data):
      if case .byteBuffer(let byteBuffer) = data.data {
        let str = byteBuffer.getString(at: 0, length: byteBuffer.readableBytes)
        print("Body ", str!)
      }
    case .headers(let headers):
      print("Headers: \(headers)")
    default:
      break
    }
    context.fireChannelRead(self.wrapInboundOut(ConnectHandler.storedByteBuffer.last!))
  }
}

final class HTTP2FrameRevertHandler: ChannelOutboundHandler {
  public typealias OutboundIn = IOData
  public typealias OutboundOut = HTTP2Frame

  func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
    print("HTTP2FrameRevertHandler")
    let incomingData = self.unwrapOutboundIn(data)
    if let frame = ConnectHandler.storedFrame.last {
      context.write(self.wrapOutboundOut(frame), promise: promise)
    }
  }
}

func makeRequest(
  channel: Channel,
  host: String,
  channelErrorForwarder: EventLoopFuture<Void>
) {
  // Step 1 is to find the HTTP2StreamMultiplexer so we can create HTTP/2 streams for our requests.
  channel.pipeline.handler(type: HTTP2StreamMultiplexer.self).map { http2Multiplexer -> Void in
    func requestStreamInitializer(
      uri: String,
      channel: Channel
    ) -> EventLoopFuture<Void> {
      channel.eventLoop.assertInEventLoop()
      let request = HTTPRequest(target: uri, headers: [], body: nil, trailers: nil)
      return channel.pipeline.addHandlers([
        HTTP2FramePayloadToHTTP1ClientCodec(httpProtocol: .https),
        SendRequestHandler(host: host, request: request)
      ], position: .last)
    }

    // Create the actual HTTP/2 stream using the multiplexer's `createStreamChannel` method.
     http2Multiplexer.createStreamChannel(promise: nil) { (channel: Channel) -> EventLoopFuture<Void> in
      // Call the above handler to initialise the stream which will send off the actual request.
      requestStreamInitializer(uri: host, channel: channel)
    }
  }
}

final class SendRequestHandler: ChannelInboundHandler {
  typealias InboundIn = HTTPClientResponsePart
  typealias InboundOut = [HTTPClientResponsePart]
  typealias OutboundOut = HTTPClientRequestPart

//  private let responseReceivedPromise: EventLoopPromise<[HTTPClientResponsePart]>
  private var responsePartAccumulator: [HTTPClientResponsePart] = []
  private let host: String
  private let compoundRequest: HTTPRequest

  init(host: String, request: HTTPRequest) {
//    self.responseReceivedPromise = responseReceivedPromise
    self.host = host
    self.compoundRequest = request
  }

  func channelActive(context: ChannelHandlerContext) {
    assert(context.channel.parent!.isActive)
    var headers = HTTPHeaders(self.compoundRequest.headers)
    headers.add(name: "host", value: self.host)
    var reqHead = HTTPRequestHead(version: self.compoundRequest.version,
                                  method: self.compoundRequest.method,
                                  uri: self.compoundRequest.target)
    reqHead.headers = headers
    context.write(self.wrapOutboundOut(.head(reqHead)), promise: nil)
    if let body = self.compoundRequest.body {
      var buffer = context.channel.allocator.buffer(capacity: body.count)
      buffer.writeBytes(body)
      context.write(self.wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
    }
    context.writeAndFlush(self.wrapOutboundOut(.end(self.compoundRequest.trailers.map(HTTPHeaders.init))), promise: nil)
    context.fireChannelActive()
  }

  func errorCaught(context: ChannelHandlerContext, error: Error) {
//    self.responseReceivedPromise.fail(error)
    context.fireErrorCaught(error)
    context.close(promise: nil)
  }

  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let resPart = self.unwrapInboundIn(data)
    self.responsePartAccumulator.append(resPart)
    if case .end = resPart {
      context.writeAndFlush(wrapInboundOut(responsePartAccumulator), promise: nil)
//      self.responseReceivedPromise.succeed(self.responsePartAccumulator)
    }
  }
}


func convertHTTP2FrameToByteBuffer(_ frame: HTTP2Frame) -> ByteBuffer? {
  var buffer = ByteBufferAllocator().buffer(capacity: 0)

  switch frame.payload {
  case .data(let data):
    if case .byteBuffer(let byteBuffer) = data.data {
      return byteBuffer
    }
    return nil
  case .headers(let headersFrame):
    return nil

  case .settings(let settingsFrame):
    return nil
  default:
    return nil // Unsupported frame type
  }

  return buffer
}
