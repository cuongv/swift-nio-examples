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
typealias X509_EXTENSION = OpaquePointer

public class X509Certificate {
  public static func issuerName(for certificate: SecCertificate) -> String? {
    let data = SecCertificateCopyData(certificate) as NSData

    var firstByte: UnsafePointer? = data.bytes.assumingMemoryBound(to: UInt8.self)
    let certificateX509: X509? = d2i_X509(nil, &firstByte, data.length)

    let issuer = issuerName(for: certificateX509)

    X509_free(certificateX509)
    return issuer
  }

  func generate_key2() -> (RSA, EVP_PKEY) {
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
    var keypair: EVP_PKEY?
    if EVP_PKEY_keygen(ctx, &keypair) <= 0 {
      // Handle error
      ERR_print_errors_fp(stderr);
      // Cleanup and return
      EVP_PKEY_free(keypair);
      EVP_PKEY_CTX_free(ctx);
    }
//    EVP_PKEY_CTX_free(ctx);
    let path = "/Users/alex.vuong/Data/Learn/SwiftNIO/swift-nio-examples/connect-proxy/Sources/generated_privatekey.pem"
    let pkey_file = fopen(path, "wb");

    var privateKey = EVP_PKEY_new()
////    unsigned char privateKey[2048]; // Assuming a sufficiently large buffer
//    let len = sizeof(privateKey);
//    var privateKey: [UInt8] = []
//    var len: UnsafeMutablePointer<Int> = UnsafeMutablePointer(2048)

//    var intValue: Int = 2048 // Your integer value
//    withUnsafeMutablePointer(to: &intValue) { intPointer in
//      // 'intPointer' is an UnsafeMutablePointer<Int> pointing to 'intValue'
//      // You can use 'intPointer' as needed
//      print(intPointer.pointee) // This will print the value 42
//      EVP_PKEY_get1_EC_KEY(
//      EVP_PKEY_get_raw_private_key(<#T##pkey: OpaquePointer!##OpaquePointer!#>, <#T##priv: UnsafeMutablePointer<UInt8>!##UnsafeMutablePointer<UInt8>!#>, <#T##len: UnsafeMutablePointer<Int>!##UnsafeMutablePointer<Int>!#>)
//      if EVP_PKEY_get_raw_private_key(keypair, &privateKey, intPointer) == 0 {
//        print("Can not get private key from keypair")
//        print(String(format: "Error signing certificate. %s", ERR_error_string(ERR_get_error(), nil)!))
//      }
//    }

    let bio = BIO_new(BIO_s_mem())
    PEM_write_bio_PrivateKey(bio, keypair, nil, nil, 0, nil, nil)
//    PEM_write_bio_RSAPrivateKey(pri, keypair, nil, nil, 0, nil, nil)

//    let pri_key = (char*)malloc(pri_len + 1);

//    EVP_PKEY_get1_RSA
//    if PEM_read_bio_PrivateKey(privateKey, nil, nil, nil) == 0 {
//      print("CAn not read")
//    }
//    BIO_read(bio, pri_key, 2048)
//    pri_key[pri_len] = '\0'

    // This is get1 function, need to handle memory soon
    let rsaKey: RSA? = EVP_PKEY_get1_RSA(keypair)
    if rsaKey == nil {
      print("Can not get private key from keypair")
      print(String(format: "Error signing certificate. %s", ERR_error_string(ERR_get_error(), nil)!))
    }

//    if EVP_PKEY_get_raw_private_key(keypair, &privateKey, len) == 0 {
//      print("Can not get private key from keypair")
//    }

    if PEM_write_PrivateKey(pkey_file, keypair, nil, nil, 0, nil, nil) == 0 {
      print("can not write file")
      print(String(format: "Error signing certificate. %s", ERR_error_string(ERR_get_error(), nil)!))
    }
    fclose(pkey_file)

//    let publicKey = EVP_PKEY_new();
//    if EVP_PKEY_copy_parameters(publicKey, keypair) <= 0 {
//      print("can not get public key")
//    }
//
//    // Extract the private key
//    let privateKey = EVP_PKEY_new();
//    if EVP_PKEY_copy_parameters(privateKey, keypair) <= 0 {
//      print("can not get private key")
//    }

    return (rsaKey!, keypair!)
  }

//  func add_ext(cert: X509, nid: Int32, value: String) -> Int {
//    var ctx = X509V3_CTX()
//
//    /* This sets the 'context' of the extensions. */
//    /* No configuration database */
//
//    ctx.db = nil
////    X509V3_set_ctx_nodb(&ctx);
//
//    /* Issuer and subject certs: both the target since it is self signed,
//     * no request and no CRL
//     */
//    X509V3_set_ctx(&ctx, cert, cert, nil, nil, 0);
//    let ex = X509V3_EXT_conf_nid(nil, &ctx, nid, value);
//    if ex == nil {
//      print("fuck u can not add ext: ", value)
//      print(String(format: "Error signing certificate. %s", ERR_error_string(ERR_get_error(), nil)!))
//      return 0
//    }
//
//    X509_add_ext(cert,ex,-1)
//    X509_EXTENSION_free(ex)
//
//    return 1
//  }

  func generate_x509(pkey: EVP_PKEY, host: String, isCA: Bool = false) -> X509? {
    /* Allocate memory for the X509 structure. */
    let x509 = X509_new()
    if x509 == nil {
      print("Unable to create X509 structure.")
      return nil
    }
    // To extract the private key
//    EVP_PKEY_new_raw_private_key_ex()

    X509_set_version(x509, 2)

    /* Set the serial number. */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    /* This certificate is valid from now until exactly one year from now. */
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 31536000);

    // Set public key?
    X509_set_pubkey(x509, pkey);

    if isCA {
//      let str = ASN1_OCTET_STRING_new()
//      let ee = "CA:TRUE"
//      ASN1_STRING_set(str, ee, Int32(ee.count))
//
//      var ext: X509_EXTENSION?
//      X509_EXTENSION_create_by_NID(&ext,NID_basic_constraints,1,str)
//      X509_add_ext(x509,ext,-1)

      // Other method
//      add_ext(x509x, NID_basic_constraints, "critical,CA:TRUE");
//      add_ext(x509x, NID_key_usage, "critical,keyCertSign,cRLSign");
//
//      add_ext(x509x, NID_subject_key_identifier, "hash");
//
//      /* Some Netscape specific extensions */
//      add_ext(x509x, NID_netscape_cert_type, "sslCA");
//
//      add_ext(x509x, NID_netscape_comment, "example comment extension");
//
//      print(String(format: "Error signing certificate. %s", ERR_error_string(ERR_get_error(), nil)!))
    }

    /* We want to copy the subject name to the issuer name. */
    let name: X509_NAME = X509_get_subject_name(x509)
    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, "CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, "imba", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, host, -1, -1, 0);

    let names = OPENSSL_sk_new_null()

    // Add DNS names to the SAN extension
    let dns_name1 = GENERAL_NAME_new();
    let str = ASN1_OCTET_STRING_new()
    let ee = host
    ASN1_STRING_set(str, ee, Int32(ee.count))
    GENERAL_NAME_set0_value(dns_name1, GEN_DNS, str)
    OPENSSL_sk_push(names, dns_name1)

//    let dns_name2 = GENERAL_NAME_new();
//    let str2 = ASN1_OCTET_STRING_new()
//    let ee2 = "*.localhost"
//    ASN1_STRING_set(str2, ee2, Int32(ee2.count))
//    GENERAL_NAME_set0_value(dns_name2, GEN_DNS, str2)
//    OPENSSL_sk_push(names, dns_name2)

    let rawPointer = UnsafeMutableRawPointer(names)
    let ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, rawPointer)
    if ext != nil {
      // Add to the end of the extension stack
      if X509_add_ext(x509, ext, -1) == 0 {
        print("added failed")
      }
      X509_EXTENSION_free(ext)
    } else {
      print(String(format: "Error signing certificate. %s", ERR_error_string(ERR_get_error(), nil)!))
    }

//    // Create the EKU extension value as an ASN1_OBJECT
//    let eku_oid = OBJ_nid2obj(NID_server_auth);
//
//    let eku_ext = X509V3_EXT_i2d(NID_server_auth, 0, eku_oid);
//    if eku_ext != nil {
//      X509_add_ext(x509, eku_ext, -1);
//      X509_EXTENSION_free(eku_ext);
//    } else {
//      print("can not add ext")
//      print(String(format: "Error signing certificate. %s", ERR_error_string(ERR_get_error(), nil)!))
//      // Handle extension creation error
//    }

//    X509_get_extended_key_usage(x509)
//    X509_set_ex_data(<#T##r: OpaquePointer!##OpaquePointer!#>, <#T##idx: Int32##Int32#>, <#T##arg: UnsafeMutableRawPointer!##UnsafeMutableRawPointer!#>)
//    X509_EXTENSION *ext = X509_get_ext(x509, extIndex);


    X509_set_subject_name(x509, name);

    /* Now set the issuer name. */
//    let issuer_name: X509_NAME = X509_NAME_new()
//    X509_NAME_add_entry_by_txt(issuer_name, "C",  MBSTRING_ASC, "CA", -1, -1, 0);
//    X509_NAME_add_entry_by_txt(issuer_name, "O",  MBSTRING_ASC, "imba", -1, -1, 0);
//    X509_NAME_add_entry_by_txt(issuer_name, "CN", MBSTRING_ASC, "127.0.0.1", -1, -1, 0);
//    X509_set_issuer_name(x509, issuer_name);


    /* Actually sign the certificate with our key. */
    // Fetch the CA key
    let caKeyPath = "/Users/alex.vuong/Data/Learn/SwiftNIO/swift-nio-examples/connect-proxy/Sources/CA/myRoot_plain.key"
    let ca_pkey_file = fopen(caKeyPath, "r");

    let cakey = PEM_read_PrivateKey(ca_pkey_file, nil, nil, nil)
    print(String(format: "Error signing certificate. %s", ERR_error_string(ERR_get_error(), nil)!))
//    let cakey = PEM_read_RSAPrivateKey(ca_pkey_file, nil, nil, nil)

    let caCertPath = "/Users/alex.vuong/Data/Learn/SwiftNIO/swift-nio-examples/connect-proxy/Sources/CA/myRoot_plain.cer"
    let ca_cert_file = fopen(caCertPath, "r");
    let ca_certificate = PEM_read_X509(ca_cert_file, nil, nil, nil)

    if X509_set_issuer_name(x509, X509_get_issuer_name(ca_certificate)) == 0 {
      print("can not set issuer name")
      print(String(format: "Error signing certificate. %s", ERR_error_string(ERR_get_error(), nil)!))
    }

    if X509_sign(x509, cakey, EVP_sha256()) == 0 {
      print(String(format: "Error signing certificate. %s", ERR_error_string(ERR_get_error(), nil)!))
      X509_free(x509);
      return nil;
    }

    let path = "/Users/alex.vuong/Data/Learn/SwiftNIO/swift-nio-examples/connect-proxy/Sources/generated_cer.pem"
    let pkey_file = fopen(path, "wb");
    if PEM_write_X509(pkey_file, x509) == 0 {
      print("can not write file")
    }
//    print(X509Certificate.issuerName(for: x509))
    print(String(format: "Error signing certificate. %s", ERR_error_string(ERR_get_error(), nil)!))
    fclose(pkey_file)

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
