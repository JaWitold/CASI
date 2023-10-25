#include <iostream>
#include <cstring>
#include <cstdlib>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

// Define the server and port
const char* PORT = "433";

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <server_address_and_path>" << std::endl;
        return 1;
    }

    // Parse the command-line argument for server address and path
    std::string url(argv[1]);
    size_t pathStart = url.find('/');
    std::string SERVER = url.substr(0, pathStart);
    std::string requestPath = url.substr(pathStart);

    SSL_library_init();
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());

    if (!ctx) {
        std::cerr << "SSL_CTX_new() failed." << std::endl;
        return 1;
    }

    SSL* ssl = SSL_new(ctx);

    if (!ssl) {
        std::cerr << "SSL_new() failed." << std::endl;
        return 1;
    }

    // Create a BIO for the SSL connection
    BIO* bio = BIO_new_ssl_connect(ctx);

    // Set the SSL connection to the server
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio, (SERVER + std::string(":") + PORT).c_str());

    // Establish the connection
    if (BIO_do_connect(bio) <= 0) {
        std::cerr << "BIO_do_connect() failed." << std::endl;
        return 1;
    }

    // Create the full HTTP GET request as a std::string
    std::string request = "GET " + std::string(requestPath) + " HTTP/1.1\r\n"
                          "Host: " + std::string(SERVER) + "\r\n"
                          "Connection: close\r\n\r\n";

    // Send the HTTP GET request
    BIO_puts(bio, request.c_str());

    // Read and print the response
    char buffer[1024];
    int bytes_read;

    while (true) {
        bytes_read = BIO_read(bio, buffer, sizeof(buffer));

        if (bytes_read <= 0) {
            break;
        }

        std::cout.write(buffer, bytes_read);
    }

    // Clean up
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    ERR_free_strings();
    EVP_cleanup();

    return 0;
}
