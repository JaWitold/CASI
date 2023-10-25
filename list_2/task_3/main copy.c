/*
 *  Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>

static const int server_port = 433;
static const char *webroot = "/home/jawitold/CASI/list_2/task_3"; // Set the directory you want to serve

typedef unsigned char bool;
#define true 1
#define false 0

/*
 * This flag won't be useful until both accept/read (TCP & SSL) methods
 * can be called with a timeout. TBD.
 */
static volatile bool server_running = true;

int create_socket()
{
    int s;
    int optval = 1;
    struct sockaddr_in addr;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    /* Reuse the address; good for quick restarts */
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
    {
        perror("setsockopt(SO_REUSEADDR) failed");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0)
    {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_server_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_chain_file(ctx, "certificate_chain.crt") <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "private.key", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}
void handle_http_request(SSL *ssl) {
    char request[1024];
    memset(request, 0, sizeof(request));

    if (SSL_read(ssl, request, sizeof(request)) <= 0) {
        ERR_print_errors_fp(stderr);
        return;
    }

    char method[16];
    char path[256];

    if (sscanf(request, "%s %s", method, path) != 2) {
        ERR_print_errors_fp(stderr);
        return;
    }

    // Ensure the request method is GET
    if (strcmp(method, "GET") != 0) {
        ERR_print_errors_fp(stderr);
        return;
    }

    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s%s", webroot, path);

    // Open and read the requested file
    int file_fd = open(filepath, O_RDONLY);
    if (file_fd == -1) {
        // File not found
        SSL_write(ssl, "HTTP/1.1 404 Not Found\r\n\r\n", 26);
        SSL_write(ssl, "404 Not Found", 13);
        close(file_fd);
        return;
    }

    struct stat file_stat;
    fstat(file_fd, &file_stat);

    SSL_write(ssl, "HTTP/1.1 200 OK\r\n", 17);
    SSL_write(ssl, "Content-Type: text/html\r\n", 25);
    SSL_write(ssl, "Connection: close\r\n", 19);
    SSL_write(ssl, "Content-Length: ", 16);

    char content_length[32];
    snprintf(content_length, sizeof(content_length), "%ld", file_stat.st_size);
    SSL_write(ssl, content_length, strlen(content_length));

    SSL_write(ssl, "\r\n\r\n", 4);

    char buffer[4096];
    int bytes_read;

    while ((bytes_read = read(file_fd, buffer, sizeof(buffer))) > 0) {
        SSL_write(ssl, buffer, bytes_read);
    }

    close(file_fd);
}

int main() {
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    int server_skt = -1;
    int client_skt = -1;

    struct sockaddr_in addr;
    unsigned int addr_len = sizeof(addr);

    signal(SIGPIPE, SIG_IGN);

    printf("\nSimple HTTP/HTTPS Server (OpenSSL) : %s : %s\n\n", __DATE__, __TIME__);

    ssl_ctx = create_context();

    printf("Server is running on port: %d\n\n", server_port);

    configure_server_context(ssl_ctx);

    server_skt = create_socket(true);

    while (server_running) {
        client_skt = accept(server_skt, (struct sockaddr *)&addr, &addr_len);
        if (client_skt < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        printf("Client TCP connection accepted\n");

        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_skt);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            server_running = false;
        } else {
            printf("Client SSL connection accepted\n\n");

            handle_http_request(ssl);

            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_skt);
        }
    }

    printf("Server exiting...\n");

    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ssl_ctx);

    if (client_skt != -1)
        close(client_skt);
    if (server_skt != -1)
        close(server_skt);

    printf("Server exiting\n");

    return EXIT_SUCCESS;
}