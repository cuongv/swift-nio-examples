#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

int generateSelfSignedCertificate(const char *certFilePath, const char *keyFilePath) {
    X509 *x509 = X509_new();
    EVP_PKEY *pkey = EVP_PKEY_new();

    // Generate a new RSA key pair
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
        fprintf(stderr, "Error assigning RSA key to EVP_PKEY\n");
        return 1;
    }

    // Set the public key in the certificate
    if (!X509_set_pubkey(x509, pkey)) {
        fprintf(stderr, "Error setting public key in the certificate\n");
        return 1;
    }

    // Set certificate information (e.g., subject, issuer, validity)
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC, (unsigned char *)"My Common Name", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    X509_set_notBefore(x509, X509_get_notBefore(x509));  // Validity start time
    X509_set_notAfter(x509, X509_get_notBefore(x509) + 31536000);  // Validity end time (1 year)
    X509_set_serialNumber(x509, 1);  // Serial number

    // Sign the certificate with the private key
    if (!X509_sign(x509, pkey, EVP_sha256())) {
        fprintf(stderr, "Error signing the certificate\n");
        return 1;
    }

    // Save the certificate and private key to files
    FILE *certFile = fopen(certFilePath, "w");
    FILE *keyFile = fopen(keyFilePath, "w");
    PEM_write_X509(certFile, x509);
    PEM_write_PrivateKey(keyFile, pkey, NULL, NULL, 0, 0, NULL);

    // Clean up
    fclose(certFile);
    fclose(keyFile);
    EVP_PKEY_free(pkey);
    X509_free(x509);

    return 0;
}

int main() {
    const char *certFilePath = "selfsigned.crt";
    const char *keyFilePath = "selfsigned.key";

    if (generateSelfSignedCertificate(certFilePath, keyFilePath) == 0) {
        printf("Self-signed certificate and private key generated successfully.\n");
    } else {
        fprintf(stderr, "Error generating the self-signed certificate.\n");
    }

    return 0;
}

