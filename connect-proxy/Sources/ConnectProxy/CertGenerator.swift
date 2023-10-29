//
//  File.swift
//  
//
//  Created by Alex Vuong on 26/10/23.
//

import Foundation
import OpenSSL
import Security

/// Create typealias' for macros not imported to Swift
typealias X509 = OpaquePointer
typealias X509_NAME = OpaquePointer
typealias EVP_PKEY = OpaquePointer
typealias RSA = OpaquePointer

public class X509Certificate {
  public static func issuerName(for certificate: SecCertificate) -> String? {
    let data = SecCertificateCopyData(certificate) as NSData

    var firstByte: UnsafePointer? = data.bytes.assumingMemoryBound(to: UInt8.self)
    let certificateX509: X509? = d2i_X509(nil, &firstByte, data.length)

    let issuer = issuerName(for: certificateX509)

    X509_free(certificateX509)
    return issuer
  }

  func generate_key() -> EVP_PKEY? {
    //    let rsa = RSA_new()
    //    // Set the public exponent for the key
    //    let e = BN_new()
    //    BN_set_word(e, RSA_F4) // RSA_F4 is a commonly used value for the public exponent
    //
    //    // Generate the RSA key pair
    //    RSA_generate_key_ex(rsa, 2048, e, nil)
    OpenSSL_add_all_algorithms()

    /* Allocate memory for the EVP_PKEY structure. */
    let pkey: EVP_PKEY? = EVP_PKEY_new()
    if pkey == nil {
      print("Unable to create EVP_PKEY structure.")
      return nil;
    }

    /* Generate the RSA key and assign it to pkey. */
//    let rsa: RSA = RSA_generate_key(2048, 65537, nil, nil)
    let rsa: RSA = RSA_new()
    let e = BN_new();
    BN_set_word(e, 0x10001); // RSA public exponent
    RSA_generate_key_ex(rsa, 2048, e, nil); // key_bits is the desired key size
    BN_free(e);

    let bytesPointer = UnsafeMutableRawPointer.allocate(byteCount: MemoryLayout<RSA>.size, alignment: 1)
    bytesPointer.storeBytes(of: rsa, as: RSA.self)

    if EVP_PKEY_assign(pkey, EVP_PKEY_RSA, bytesPointer) == 0 {
      print("Unable to generate 2048-bit RSA key.")
      EVP_PKEY_free(pkey);
      return nil;
    }

    /* The key has been generated, return it. */
    return pkey;
  }

  func generate_key2() -> EVP_PKEY? {
    // Create an EVP key context for RSA key generation
    let ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nil);

    // Set RSA key generation parameters (key size and public exponent)
    let key_bits: Int32 = 2048
    let pubexp = BN_new();
    BN_set_word(pubexp, 65537)

    if EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_bits) <= 0 {
      //        || EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, pubexp) <= 0)
      // Handle error
      ERR_print_errors_fp(stderr);
      // Cleanup and return
      EVP_PKEY_CTX_free(ctx);
      // ...
    }

    // Generate the RSA key pair
    var key: EVP_PKEY?
    if EVP_PKEY_keygen(ctx, &key) <= 0 {
      // Handle error
      ERR_print_errors_fp(stderr);
      // Cleanup and return
      EVP_PKEY_free(key);
      EVP_PKEY_CTX_free(ctx);
    }
    EVP_PKEY_CTX_free(ctx);
    return key
  }

  func generate_x509(pkey: EVP_PKEY) -> X509? {
    /* Allocate memory for the X509 structure. */
    let x509 = X509_new()
    if x509 == nil {
      print("Unable to create X509 structure.")
      return nil
    }
    /* Set the serial number. */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    /* This certificate is valid from now until exactly one year from now. */
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 31536000);
    /* Set the public key for our certificate. */
    X509_set_pubkey(x509, pkey);
    /* We want to copy the subject name to the issuer name. */
    let name: X509_NAME = X509_get_subject_name(x509);
    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, "CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, "imba", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, "localhost", -1, -1, 0);
    /* Now set the issuer name. */
    X509_set_issuer_name(x509, name);
    /* Actually sign the certificate with our key. */
    if X509_sign(x509, pkey, EVP_sha1()) == 0 {
      print(String(format: "Error signing certificate. %s", ERR_error_string(ERR_get_error(), nil)!))
      X509_free(x509);
      return nil;
    }

    return x509;
  }

  //MARK: - Private
  private static func issuerName(for x509Certificate: X509?) -> String? {
    var issuer: String?
    guard let x509Certificate = x509Certificate else {
      return nil
    }

    let issuerName = X509_get_issuer_name(x509Certificate)
    let nid = NID_commonName
    let index = X509_NAME_get_index_by_NID(issuerName, nid, -1)

    if let issuerNameEntry /*X509_NAME_ENTRY*/ = X509_NAME_get_entry(issuerName, index) {
      if let issuerNameASN1 = X509_NAME_ENTRY_get_data(issuerNameEntry),
         let issuerNameUTF8 = ASN1_STRING_get0_data(issuerNameASN1) { // string rep of DES ASN1 structure
        issuer = String(cString: issuerNameUTF8)
      }
    }
    return issuer
  }
}

class CertGenerator {
  init() {
    //    SSL_library_init()

    //    let x509 = X509()
    //    X509 *x509 = X509_new();


    //    let generator = KeyPairGenerator()
    //    generator.generateKeyPair()
  }
}

class KeyPairGenerator {
  let publicKeyIdentifier: [UInt8] = [UInt8]("com.apple.sample.publickey\0".utf8)
  let privateKeyIdentifier: [UInt8] = [UInt8]("com.apple.sample.privatekey\0".utf8)

  func generateKeyPair() {
    var status: OSStatus = noErr
    var privateKeyAttr: [String: Any] = [:]
    var publicKeyAttr: [String: Any] = [:]
    var keyPairAttr: [String: Any] = [:]

    let publicTag = Data(bytes: publicKeyIdentifier, count: publicKeyIdentifier.count)
    let privateTag = Data(bytes: privateKeyIdentifier, count: privateKeyIdentifier.count)

    var publicKey: SecKey?
    var privateKey: SecKey?

    keyPairAttr[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
    keyPairAttr[kSecAttrKeySizeInBits as String] = 1024

    privateKeyAttr[kSecAttrIsPermanent as String] = true
    privateKeyAttr[kSecAttrApplicationTag as String] = privateTag

    publicKeyAttr[kSecAttrIsPermanent as String] = true
    publicKeyAttr[kSecAttrApplicationTag as String] = publicTag

    keyPairAttr[kSecPrivateKeyAttrs as String] = privateKeyAttr
    keyPairAttr[kSecPublicKeyAttrs as String] = publicKeyAttr

    status = SecKeyGeneratePair(keyPairAttr as CFDictionary, &publicKey, &privateKey)

    // Handle errors if necessary...

    if publicKeyAttr.isEmpty == false { publicKeyAttr.removeAll() }
    if privateKeyAttr.isEmpty == false { privateKeyAttr.removeAll() }
    if keyPairAttr.isEmpty == false { keyPairAttr.removeAll() }
    if publicKey != nil { publicKey = nil }
    if privateKey != nil { privateKey = nil }
  }

  //  func generateSelfSignedCertificate() {
  //    let attributes: [String: Any] = [
  //      kSecAttrKeySizeInBits as String: 2048,
  //      kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
  //    ]
  //    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, nil) else {
  //      print("Failed to create a private key")
  //      return
  //    }
  //
  //    let commonName = "Your Common Name"
  //    let certificateAttributes: [String: Any] = [
  //      kSecAttrIsPermanent as String: kCFBooleanTrue,
  //      kSecAttrLabel as String: "Self-Signed Certificate",
  //      kSecAttrSubject as String: [
  //        wName as String: commonName
  //      ]
  //    ]
  //
  //    guard let certificate = SecCertificateCreateWithAttributes(nil, certificateAttributes as CFDictionary, privateKey) else {
  //      print("Failed to create a certificate")
  //      return
  //    }
  //
  //    let identity = SecIdentityCreateWithCertificate(nil, certificate, privateKey)
  //
  //    // Optionally, you can add the certificate and private key to the keychain.
  //
  //    // Dispose of resources.
  //    SecKeyCopyExternalRepresentation(privateKey, nil)
  //    SecCertificateCopyData(certificate)
  //    SecIdentityCopyCertificate(identity, nil)
  //  }
}

