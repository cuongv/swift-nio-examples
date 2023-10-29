///===----------------------------------------------------------------------===//
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

final class GlueAndForwarderHandler {
  private var partner: GlueAndForwarderHandler?
  private var context: ChannelHandlerContext?
  private var pendingRead: Bool = false
  private init() { }
}

extension GlueAndForwarderHandler {
  static func matchedPair() -> (GlueAndForwarderHandler, GlueAndForwarderHandler) {
    let first = GlueAndForwarderHandler()
    let second = GlueAndForwarderHandler()

    first.partner = second
    second.partner = first
    return (first, second)
  }
}


extension GlueAndForwarderHandler {
  private func partnerWrite(_ data: NIOAny) {
    self.context?.write(data, promise: nil)
  }

  private func partnerFlush() {
    self.context?.flush()
  }

  private func partnerWriteEOF() {
    self.context?.close(mode: .output, promise: nil)
  }

  private func partnerCloseFull() {
    self.context?.close(promise: nil)
  }

  private func partnerBecameWritable() {
    if self.pendingRead {
      self.pendingRead = false
      self.context?.read()
    }
  }

  private var partnerWritable: Bool {
    self.context?.channel.isWritable ?? false
  }
}


extension GlueAndForwarderHandler: ChannelDuplexHandler {
  typealias InboundIn = NIOAny
  typealias OutboundIn = NIOAny
  typealias OutboundOut = NIOAny

  func handlerAdded(context: ChannelHandlerContext) {
    self.context = context
  }

  func handlerRemoved(context: ChannelHandlerContext) {
    self.context = nil
    self.partner = nil
  }

  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    self.partner?.partnerWrite(data)
  }

  func channelReadComplete(context: ChannelHandlerContext) {
    self.partner?.partnerFlush()
  }

  func channelInactive(context: ChannelHandlerContext) {
    self.partner?.partnerCloseFull()
  }

  func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
    if let event = event as? ChannelEvent, case .inputClosed = event {
      self.partner?.partnerWriteEOF()
    }
  }

  func errorCaught(context: ChannelHandlerContext, error: Error) {
    self.partner?.partnerCloseFull()
  }

  func channelWritabilityChanged(context: ChannelHandlerContext) {
    if context.channel.isWritable {
      self.partner?.partnerBecameWritable()
    }
  }

  func read(context: ChannelHandlerContext) {
    if let partner = self.partner, partner.partnerWritable {
      context.read()
    } else {
      self.pendingRead = true
    }
  }
}
