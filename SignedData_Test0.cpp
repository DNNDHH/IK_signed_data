#include <iostream>
#include <string>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

std::string make_signed_data(RSA* rsa_key, const std::string& hash_algorithm, const std::string& idempotency_key) {

    if (hash_algorithm.empty()) {
        return "无算法";
    }


    std::vector<unsigned char> key_bytes(idempotency_key.begin(), idempotency_key.end());

    unsigned int signature_length;
    std::vector<unsigned char> signature(RSA_size(rsa_key));
    if (RSA_sign(EVP_PKEY_RSA, reinterpret_cast<const unsigned char*>(key_bytes.data()), key_bytes.size(),
                 signature.data(), &signature_length, rsa_key) != 1) {

        return "Signature错误";
    }


    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, signature.data(), signature_length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);
    std::string base64_signature(bufferPtr->data, bufferPtr->length);
    return base64_signature;
}

int main() {

    RSA* rsa_key = nullptr; 
    OpenSSL_add_all_algorithms();

    std::string hash_algorithm = "SHA256";
    std::string idempotency_key = "idempotencykey";


    std::string signed_data = make_signed_data(rsa_key, hash_algorithm, idempotency_key);

    std::cout << "idempotencyKeySignature: " << signed_data << std::endl;

    RSA_free(rsa_key);
    ERR_free_strings();
    EVP_cleanup();
    return 0;
}
