#include "proxy.h"
#include <openssl/x509v3.h>

int set_nonblocking(int socket_fd) {
    // Get the current file descriptor flags
    int flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl(F_GETFL) failed");
        return -1;
    }

    // Set the socket to non-blocking mode
    if (fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl(F_SETFL) failed");
        return -1;
    }

    return 0; // Success
}

void init_SSL(void) {
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
}

void destroy_SSL(void) {
    ERR_free_strings();
    EVP_cleanup();
}

void shutdown_SSL(SSL* cSSL) {
    SSL_shutdown(cSSL);
    SSL_free(cSSL);
}


SOCKET create_server_socket(const char *port) {
    printf("Configuring local address...\n");
    // Establish server variables
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *bind_address;
    getaddrinfo(0, port, &hints, &bind_address);

    // Create Socket
    printf("Creating socket...\n");
    SOCKET socket_listen;

    // Allow port resuse
    // int opt = 1;
    // setsockopt(socket_listen, SOL_SOCKET, SO_REUSEADDR, (const void*)&opt, sizeof(int));

    socket_listen = socket(bind_address->ai_family,
            bind_address->ai_socktype, bind_address->ai_protocol);
    
    if (!ISVALIDSOCKET(socket_listen)) {
        fprintf(stderr, "socket() failed. (%d)\n", GETSOCKETERRNO());
        exit(1);
    }
    
    // Bind socket with address
    printf("Binding socket to local address...\n");
    if (bind(socket_listen,
             bind_address->ai_addr, bind_address->ai_addrlen)) {
        fprintf(stderr, "bind() failed. (%d)\n", GETSOCKETERRNO());
        exit(1);
    }
    freeaddrinfo(bind_address);

    // Listen
    printf("Listening...\n");
    if (listen(socket_listen, 10) < 0) {
        fprintf(stderr, "listen() failed. (%d)\n", GETSOCKETERRNO());
        exit(1);
    }

    return socket_listen;
}

int send_200(SOCKET client) {
    const char* c200 = "HTTP/1.1 200 Connection Established\r\n\r\n";
    int bytes_writ = send(client, c200, strlen(c200), 0);
    if (bytes_writ < 0) {
        fprintf(stderr, "Error sending 200 message to client\n");
        return -1;
    }
    return 0;
    printf("200 message successfully sent\n");
}

// void forward_request(char* buffer) {
//     printf("placeholder\n");
// }

SOCKET connect_to_host(char *hostname, char *port) {
    printf("Configuring remote address...\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;
    struct addrinfo *peer_address;
    if (getaddrinfo(hostname, port, &hints, &peer_address)) {
        fprintf(stderr, "getaddrinfo() failed. (%d)\n", GETSOCKETERRNO());
        return -1;
    }
    fprintf(stderr,"Configuring remote address for host: %s, port: %s\n", hostname, port);  
    
    // Use strncmp to compare the port with "9049"
//     if (strncmp(port, "9049", 4) == 0) {
//         printf("Port is correct: %s\n", port);
//     } else {
//         printf("Port is incorrect: %s (expected 9049)\n", port);
//     }

    printf("Remote address is: ");
    char address_buffer[100];
    char service_buffer[100];
    getnameinfo(peer_address->ai_addr, peer_address->ai_addrlen,
            address_buffer, sizeof(address_buffer),
            service_buffer, sizeof(service_buffer),
            NI_NUMERICHOST);
    printf("%s %s\n", address_buffer, service_buffer);

    printf("Creating socket...\n");
    SOCKET server;
    server = socket(peer_address->ai_family,
            peer_address->ai_socktype, peer_address->ai_protocol);
    if (!ISVALIDSOCKET(server)) {
        fprintf(stderr, "socket() failed. (%d)\n", GETSOCKETERRNO());
        return -1;
    }

    printf("Connecting...\n");
    if (connect(server,
                peer_address->ai_addr, peer_address->ai_addrlen)) {
        fprintf(stderr, "connect() failed. (%d)\n", GETSOCKETERRNO());
        return -1;
    }
    freeaddrinfo(peer_address);

    printf("Connected.\n\n");

    return server;
}

// Load root private key
EVP_PKEY *load_root_key(const char *key_path) {
    FILE *key_file = fopen(key_path, "r");
    if (!key_file) {
        perror("Failed to open root key file");
        return NULL;
    }
    EVP_PKEY *root_key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    
    fclose(key_file);
    return root_key;
}

// Load root certificate
X509 *load_root_cert(const char *cert_path) {
    FILE *cert_file = fopen(cert_path, "r");
    if (!cert_file) {
        perror("Failed to open root cert file");
        return NULL;
    }

    X509 *root_cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    return root_cert;
}

X509_EXTENSION *create_san_extension(const char *hostname) {
    char san_buffer[256];
    snprintf(san_buffer, sizeof(san_buffer), "DNS:%s", hostname);
    X509_EXTENSION *san_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san_buffer);
    return san_ext;
}

X509 *generate_client_cert(X509 *root_cert, EVP_PKEY *root_key, const char *hostname, EVP_PKEY **client_key) {
    if (!client_key) {
        fprintf(stderr, "client_key pointer is null.\n");
        return NULL;
    }

    // Allocate memory for client key
    *client_key = EVP_PKEY_new();  
    if (!*client_key) {
        fprintf(stderr, "Failed to create new EVP_PKEY object.\n");
        return NULL;
    }

    // Create RSA key using EVP_PKEY context
    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pkey_ctx || EVP_PKEY_keygen_init(pkey_ctx) <= 0) {
        fprintf(stderr, "Failed to initialize RSA key generation.\n");
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(*client_key);
        return NULL;
    }

    // Set RSA key size (2048 bits)
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 2048) <= 0) {
        fprintf(stderr, "Failed to set RSA key size.\n");
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(*client_key);
        return NULL;
    }

    // Generate the RSA key
    if (EVP_PKEY_keygen(pkey_ctx, client_key) <= 0) {
        fprintf(stderr, "Failed to generate RSA key.\n");
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(*client_key);
        return NULL;
    }

    EVP_PKEY_CTX_free(pkey_ctx);  // Free the key generation context

    // Create and configure the certificate
    X509 *client_cert = X509_new();
    if (!client_cert) {
        fprintf(stderr, "Failed to create new X509 certificate.\n");
        EVP_PKEY_free(*client_key);
        return NULL;
    }

    // Set certificate properties
    X509_set_version(client_cert, 2); // X.509 v3
  ASN1_INTEGER *serial = ASN1_INTEGER_new();
BIGNUM *bn = BN_new();
BN_rand(bn, 64, 0, 0); // Generate a random 64-bit number
BN_to_ASN1_INTEGER(bn, serial);
X509_set_serialNumber(client_cert, serial);
BN_free(bn);
ASN1_INTEGER_free(serial);
    X509_gmtime_adj(X509_get_notBefore(client_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(client_cert), 365 * 24 * 60 * 60); // 1 year validity

    // Set issuer and subject names
    X509_set_issuer_name(client_cert, X509_get_subject_name(root_cert));
    X509_NAME *name = X509_get_subject_name(client_cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)hostname, -1, -1, 0);
    X509_set_subject_name(client_cert, name);

    // Add Subject Key Identifier
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_key_identifier, "hash");
    if (ext) {
        X509_add_ext(client_cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    // // Add Authority Key Identifier
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_authority_key_identifier, "keyid:always,issuer");
    if (ext) {
        X509_add_ext(client_cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    // Add Basic Constraints (CA:FALSE)
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "CA:FALSE");
    if (ext) {
        X509_add_ext(client_cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    // // Add Key Usage (Digital Signature, Key Encipherment)
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, "digitalSignature,keyEncipherment");
    if (ext) {
        X509_add_ext(client_cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    // // Add Extended Key Usage (Client and Server Authentication)
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "clientAuth,serverAuth");
    if (ext) {
        X509_add_ext(client_cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    // Add SAN 
    X509_EXTENSION *san_ext = create_san_extension(hostname);
    if (san_ext) {
        X509_add_ext(client_cert, san_ext, -1);
        X509_EXTENSION_free(san_ext);
    } else {
        fprintf(stderr, "Failed to create SAN extension.\n");
    }

    // Attach client key to the certificate
    X509_set_pubkey(client_cert, *client_key);

    // Sign the certificate with the root key
    if (!X509_sign(client_cert, root_key, EVP_sha256())) {
        fprintf(stderr, "Failed to sign client certificate.\n");
        X509_free(client_cert);
        EVP_PKEY_free(*client_key);
        return NULL;
    }

    // Return the generated certificate
    return client_cert;
}



// Set up SSL Context for the client connection
SSL_CTX *setup_ssl_context(X509 *client_cert, EVP_PKEY *client_key) {
    
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
     SSL_CTX_set_alpn_protos(ctx, (unsigned char *)"\x08http/1.1\x02h2", 11);
    //SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    //SSL_CTX_set_cipher_list(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256");

    if (!SSL_CTX_use_certificate(ctx, client_cert)) {
        perror("Failed to use client certificate");
        return NULL;
    }

    if (!SSL_CTX_use_PrivateKey(ctx, client_key)) {
        perror("Failed to use client private key");
        return NULL;
    }

    return ctx;
}




SSL* ssl_with_server(int server_socket) {
    SSL_CTX *ctx;
    SSL *ssl;
   
    // Initialize OpenSSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create SSL context
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    // if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
    //     fprintf(stderr, "Failed to set min TLS version: %s\n", ERR_reason_error_string(ERR_get_error()));
    //     SSL_CTX_free(ctx);
    //     return NULL;
    // }

    // Create an SSL object and associate it with the socket
    ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "Failed to create SSL object\n");
        ERR_print_errors_fp(stderr);
       
        SSL_CTX_free(ctx);
        return NULL;
    }
    // if (!SSL_set_tlsext_host_name(ssl, hostname)) {
    //     fprintf(stderr, "Failed to set SNI: %s\n", ERR_reason_error_string(ERR_get_error()));
    //     SSL_free(ssl);
    //     SSL_CTX_free(ctx);
    //     return NULL;
    // }

    SSL_set_fd(ssl, server_socket);

    // 5. Perform the SSL/TLS handshake
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "SSL handshake failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
       
        SSL_CTX_free(ctx);
        return NULL;
    }


    printf("SSL/TLS handshake successful with server\n");
    return ssl;
}

// int main(int argc, char *argv[]) {
//     if (argc != 3) {
//         fprintf(stderr, "Usage: %s <hostname> <port>\n", argv[0]);
//         exit(EXIT_FAILURE);
//     }

//     const char *hostname = argv[1];
//     int port = atoi(argv[2]);

//     ssl_client(hostname, port);

//     return 0;
// }











