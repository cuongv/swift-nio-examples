//
//  File.swift
//  
//
//  Created by Alex Vuong on 8/11/23.
//

import NIOCore
import NIOTLS

final class HTTPVersionDetectorHandler: ChannelInboundHandler {
  typealias InboundIn = ByteBuffer
  private(set) var negotiatedProtocol: String?

  func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
    print("userInboundEventTriggered", event)
    if let event = event as? TLSUserEvent, case .handshakeCompleted(let negotiatedProtocol) = event {
      self.negotiatedProtocol = negotiatedProtocol
    }
    context.fireUserInboundEventTriggered(event)
  }
}
