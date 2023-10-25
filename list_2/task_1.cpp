#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <iomanip>

// Function to compute a hash of a file using OpenSSL
std::string computeHash(const std::string& filename, const EVP_MD* hashFunction) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        std::cerr << "Error creating context" << std::endl;
        return "";
    }

    if (1 != EVP_DigestInit_ex(mdctx, hashFunction, nullptr)) {
        std::cerr << "Error initializing digest" << std::endl;
        return "";
    }

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file" << std::endl;
        return "";
    }

    char buffer[1024];
    while (file.read(buffer, sizeof(buffer))) {
        if (1 != EVP_DigestUpdate(mdctx, buffer, sizeof(buffer))) {
            std::cerr << "Error updating digest" << std::endl;
            return "";
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hashLen)) {
        std::cerr << "Error finalizing digest" << std::endl;
        return "";
    }

    EVP_MD_CTX_free(mdctx);

    std::stringstream result;
    result << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < hashLen; i++) {
        result << std::setw(2) << static_cast<int>(hash[i]);
    }

    return result.str();
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <filename>" << std::endl;
        return 1;
    }

    const std::string filename = argv[1];

    const EVP_MD* hashFunctions[] = {
        EVP_blake2b512(),
        EVP_blake2s256(),
        EVP_md5(),
        EVP_sha1(),
        EVP_sha256(),
        EVP_sha3_256()
    };

    for (const auto& hashFunction : hashFunctions) {
        std::string hash = computeHash(filename, hashFunction);
        if (!hash.empty()) {
            std::cout << EVP_MD_name(hashFunction) << " Hash: " << hash << std::endl;
        }
    }

    return 0;
}
