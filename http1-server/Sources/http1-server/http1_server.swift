import Foundation
import NIO
import NIOHTTP1
import NIOHTTP2
import NIOSSL
import NetworkExtension


@main
public struct http1_server {
  public static func main() {

//    let vpnManager = NEVPNManager.shared();
//    let proxySettings = NEProxySettings()
//
//    // HTTP proxy settings
//    let httpProxy = NEProxyServer(address: "proxy-server-address", port: 8080)
//    proxySettings.httpEnabled = true
//    proxySettings.httpServer = httpProxy
//
//    // HTTPS proxy settings
//    let httpsProxy = NEProxyServer(address: "proxy-server-address", port: 8080)
//    proxySettings.httpsEnabled = true
//    proxySettings.httpServer = httpsProxy
//
//    VPNIKEv2Setup.connectVPN()

    // Apply the proxy settings
//    let manager =  NEProxySettingsManager.shared()
//    manager.loadFromPreferences { preferences, error in
//        if error == nil {
//            preferences?.protocolConfiguration?.proxySettings = proxySettings
//            manager.saveToPreferences(completionHandler: { error in
//                if error == nil {
//                    print("Proxy settings applied.")
//                }
//            })
//        }
//    }

    // Set up the TLS configuration, it's important to set the `applicationProtocols` to
    // `NIOHTTP2SupportedALPNProtocols` which (using ALPN (https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation))
    // advertises the support of HTTP/2 to the client.
    //var serverConfig = TLSConfiguration.makeServerConfiguration(certificateChain: [sslCertificate], privateKey: sslPrivateKey)

    let cert = "/users/alex.vuong/data/learn/swiftnio/swift-nio-examples/connect-proxy/sources/generated_cer.pem"
    let privateKey = "/users/alex.vuong/data/learn/swiftnio/swift-nio-examples/connect-proxy/sources/generated_privatekey.pem"

//    let cert = "/users/alex.vuong/data/learn/swiftnio/swift-nio-examples/connect-proxy/sources/cuongv-self-cert.pem"
//    let privateKey = "/users/alex.vuong/data/learn/swiftnio/swift-nio-examples/connect-proxy/sources/cuongv-private-key.pem"

    var serverConfig = TLSConfiguration.makeServerConfiguration(
      certificateChain: try! NIOSSLCertificate.fromPEMFile(cert).map { .certificate($0) },
      privateKey: .file(privateKey)
    )
    serverConfig.applicationProtocols = ["http/1.1"] //NIOHTTP2SupportedALPNProtocols

    // Configure the SSL context that is used by all SSL handlers.
    let sslContext = try! NIOSSLContext(configuration: serverConfig)

    let group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
    let bootstrap = ServerBootstrap(group: group)
    // Set up our ServerChannel
      .serverChannelOption(ChannelOptions.backlog, value: 256)
      .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)

    //Set up the closure that will be used to initialise Child channels
    // (when a connection is accepted to our server)
      .childChannelInitializer { channel in

//        HTTPServerUpgradeHandler to upgrade to another type of protocol such as websocket

        channel.pipeline.addHandlers([
          NIOSSLServerHandler(context: sslContext),
        ])
        .flatMap {
          channel.pipeline.configureHTTPServerPipeline()
        }
        .flatMap {
          channel.pipeline.addHandlers([
            HTTP1Handler()
          ])
        }
      }

    // Set up child channel options
      .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
      .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 16)
      .childChannelOption(ChannelOptions.recvAllocator, value: AdaptiveRecvByteBufferAllocator())

    let defaultHost = "127.0.0.1"
    let defaultPort = 9090

    let channel = try? bootstrap.bind(host: defaultHost, port: defaultPort).wait()
    print("Server started and listening on \(channel!.localAddress!)")
    try? channel!.closeFuture.wait()
    print("Server closed")
  }
}
