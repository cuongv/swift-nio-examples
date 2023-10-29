//
//  File.swift
//  
//
//  Created by Alex Vuong on 26/10/23.
//

import NIO

final class LogHandler: ChannelInboundHandler {
  public typealias InboundIn = ByteBuffer
  public typealias InboundOut = ByteBuffer

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    print("channel read")
    let inBuff = self.unwrapInboundIn(data)
    let str = inBuff.getString(at: 0, length: inBuff.readableBytes) ?? ""
    print(inBuff.readableBytes)
    print(str)
    let result = "\u{1B}[32m\(str)\u{1B}[0m"
    var buff = context.channel.allocator.buffer(capacity: result.count)
    buff.writeString(result)
    context.write(self.wrapInboundOut(buff), promise: nil)
  }

  public func channelReadComplete(context: ChannelHandlerContext) {
    print("Channel read completed!")
  }

  public func errorCaught(context: ChannelHandlerContext, error: Error) {
    print(error)
  }
}
