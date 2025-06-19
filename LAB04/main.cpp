#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <string>

void print_public_key(EVP_PKEY* pubkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    EVP_PKEY_print_public(bio, pubkey, 0, nullptr);
    char* key_str = nullptr;
    long key_len = BIO_get_mem_data(bio, &key_str);
    std::cout << "\nSubject Public Key:\n";
    std::cout.write(key_str, key_len) << std::endl;
    BIO_free(bio);
}

void print_signature(X509* cert) {
    const ASN1_BIT_STRING* sig;
    const X509_ALGOR* sig_alg;
    X509_get0_signature(&sig, &sig_alg, cert);
    
    std::cout << "\nSignature Value: ";
    for (int i = 0; i < sig->length; i++) {
        printf("%02x", sig->data[i]);
    }
    std::cout << std::endl;
}

EVP_PKEY* parse_certificate(const std::string& cert_path, bool is_pem) {
    FILE* fp = fopen(cert_path.c_str(), "r");
    if (!fp) {
        std::cerr << "Error: Cannot open certificate file" << std::endl;
        return nullptr;
    }

    X509* cert = nullptr;
    if (is_pem) {
        cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    } else {
        cert = d2i_X509_fp(fp, nullptr);
    }
    fclose(fp);

    if (!cert) {
        std::cerr << "Error: Cannot read certificate" << std::endl;
        return nullptr;
    }

    std::cout << "\n=== Certificate Details ===\n" << std::endl;
    
    // Subject name with detailed fields
    X509_NAME* subject_name = X509_get_subject_name(cert);
    BIO* bio = BIO_new(BIO_s_mem());
    X509_NAME_print_ex(bio, subject_name, 0, XN_FLAG_ONELINE);
    char* subject = nullptr;
    long len = BIO_get_mem_data(bio, &subject);
    std::cout << "Subject: ";
    std::cout.write(subject, len) << std::endl;
    BIO_reset(bio);

    // Validity period
    const ASN1_TIME* not_before = X509_get0_notBefore(cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(cert);
    
    std::cout << "\nValidity Period:" << std::endl;
    std::cout << "Not Before: ";
    ASN1_TIME_print(bio, not_before);
    char* date_str = nullptr;
    long date_len = BIO_get_mem_data(bio, &date_str);
    std::cout.write(date_str, date_len) << std::endl;
    
    BIO_reset(bio);
    std::cout << "Not After: ";
    ASN1_TIME_print(bio, not_after);
    date_len = BIO_get_mem_data(bio, &date_str);
    std::cout.write(date_str, date_len) << std::endl;
    BIO_free(bio);

    // Signature algorithm
    const X509_ALGOR* sig_alg;
    const X509_ALGOR* unused;
    X509_get0_signature(nullptr, &sig_alg, cert);
    char sig_alg_name[256];
    OBJ_obj2txt(sig_alg_name, sizeof(sig_alg_name), sig_alg->algorithm, 0);
    std::cout << "\nSignature Algorithm: " << sig_alg_name << std::endl;

    // Print signature value
    print_signature(cert);

    // Get and verify public key
    EVP_PKEY* pubkey = X509_get_pubkey(cert);
    if (!pubkey) {
        std::cerr << "Error: Unable to get public key" << std::endl;
        X509_free(cert);
        return nullptr;
    }

    // Print public key details
    print_public_key(pubkey);

    // Verify certificate signature
    int verify_result = X509_verify(cert, pubkey);
    if (verify_result != 1) {
        std::cerr << "\nError: Certificate signature verification failed" << std::endl;
        EVP_PKEY_free(pubkey);
        X509_free(cert);
        return nullptr;
    }

    std::cout << "\nSignature verification successful!" << std::endl;
    X509_free(cert);
    return pubkey;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <certificate_path> <format>" << std::endl;
        std::cerr << "Format: pem or der" << std::endl;
        return 1;
    }

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    std::string cert_path = argv[1];
    bool is_pem = (std::string(argv[2]) == "pem");

    EVP_PKEY* pubkey = parse_certificate(cert_path, is_pem);
    if (pubkey) {
        std::cout << "Public key retrieved successfully" << std::endl;
        EVP_PKEY_free(pubkey);
    }

    // Cleanup OpenSSL
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}