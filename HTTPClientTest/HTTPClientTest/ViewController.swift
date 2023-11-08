//
//  ViewController.swift
//  HTTPClientTest
//
//  Created by Alex Vuong on 30/10/23.
//

import Cocoa
import Security

class ViewController: NSViewController {
  override func viewDidLoad() {
    super.viewDidLoad()

    let request = URLRequest(url: URL(string: "https://p.stg-myteksi.com:443")!)
    let session = URLSession(configuration: .ephemeral)
    session.dataTask(with: request) { data, response, error in
      if error != nil {
        print(error!)
      } else {
        if let httpResponse = response as? HTTPURLResponse {
          for (key, value) in httpResponse.allHeaderFields.enumerated() {
            print("value and key: ", value, key)
          }
//          print("headers:", httpResponse.allHeaderFields.keys)
//          let httpVersion = httpResponse.httpVersion
//          print("HTTP Version: \(httpVersion)")
        }

//        print(String(decoding: data!, as: UTF8.self))
      }
    }
    .resume()

    fetchServerCertificate(forHost: "p.stg-myteksi.com:443", port: 443)
  }

  func fetchServerCertificate(forHost host: String, port: Int) {
    let url = URL(string: "https://\(host):\(port)")!

    let session = URLSession(configuration: .default, delegate: TrustingURLSessionDelegate(), delegateQueue: nil)
    let task = session.dataTask(with: url) { (data, response, error) in
      if let error = error {
        print("Error: \(error)")
      } else if let data = data {
        let str = String(data: data, encoding: .utf8)
        print("Data received successfully: ", str!)
      }
    }

    task.resume()
  }

  // URLSession delegate for SSL certificate validation
  class TrustingURLSessionDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
      if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
        let serverTrust = challenge.protectionSpace.serverTrust
        var secResult = SecTrustResultType.invalid
        let status = SecTrustEvaluate(serverTrust!, &secResult)

        if status == errSecSuccess, (secResult == .proceed || secResult == .unspecified) {
          // The server's certificate is trusted
          let cre = URLCredential(trust: serverTrust!)
          //          SecCertificate
          //          cre.certificates
          completionHandler(.useCredential, URLCredential(trust: serverTrust!))

          if let certificate = SecTrustGetCertificateAtIndex(serverTrust!, 0) {
//            SecTrustCopyCertificateChain(serverTrust)[0] {
            let keys: [CFString] = [kSecOIDSubjectAltName]
            let keyRefs = keys as CFArray

            let values = SecCertificateCopyValues(certificate, nil, nil) as! [String: Any]
            for key in values.keys {
              print(values[key]!)
            }

            /*
            // Extract the Common Name (CN)
            if let commonName = extractCommonName(fromCertificate: certificate) {
              print("Common Name (CN): \(commonName)")
            }

            // Extract Subject Alternative Names (SAN)
            if let subjectAltNames = extractSubjectAltNames(fromCertificate: certificate) {
              for san in subjectAltNames {
                print("Subject Alternative Name (SAN): \(san)")
              }
            }
             */
          }

          return
        }
      }

      // In other cases, you might want to reject the certificate, e.g., by calling completionHandler(.cancelAuthenticationChallenge, nil)
      completionHandler(.performDefaultHandling, nil)
    }

    func extractCommonName(fromCertificate certificate: SecCertificate) -> String? {
      // Get the subject summary
      if let summary = SecCertificateCopySubjectSummary(certificate) {
        return summary as String
      }
      return nil
    }

    func extractSubjectAltNames(fromCertificate certificate: SecCertificate) -> [String]? {
      // Create a dictionary to specify the desired certificate information


      let keys: [CFString] = [kSecOIDSubjectAltName]
      let keyRefs = keys.map { $0 as! CFString } as CFArray

      // Retrieve the certificate information
      if let values = SecCertificateCopyValues(certificate, keyRefs, nil) {
        var subjectAltNames: [String] = []
        print(values)

//        for key in values [CFDictionary] {
//          if let san = key[kSecPropertyKeyValue] as? [String] {
//            for name in san {
//              subjectAltNames.append(name)
//            }
//          }
//        }

        return subjectAltNames
      }

      return nil
    }
  }


  override var representedObject: Any? {
    didSet {
      // Update the view, if already loaded.
    }
  }
}

