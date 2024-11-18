#include "proxy.h"

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

// Generate a new cert for each client; root CA signs cert
/*X509 *generate_client_cert(X509 *root_cert, EVP_PKEY *root_key, const char *hostname) {
    X509 *client_cert = X509_new();
    EVP_PKEY *client_key = EVP_PKEY_new();
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    EVP_PKEY_assign_RSA(client_key, rsa);

    // Set cert version & cert serial num
    X509_set_version(client_cert, 2); //X.509v3
    ASN1_INTEGER_set(X509_get_serialNumber(client_cert), 1); // Incr each cert

    // Set validity period
    x509_gmtime_adj(X509_get_notBefore(client_cert), 0);
    // Cert good for 1 year
    X509_gmtime_adj(X509_get_notAfter(client_cert), 365 * 24 * 60 * 60);

    // Set issuer name (root CA)
    X509_set_issuer_name(client_cert, X509_get_subject_name(root_cert));

    // Set subject name (hostname)
    X509_NAME *name = X509_get_subject_name(client_cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, 
                              (unsigned char *) hostname, -1, -1, 0);
    X509_set_subject_name(client_cert, name);

    // Attach client key to cert
    X509_set_pubkey(client_cert, client_key);

    // Sign certificate with root key
    if (!X509_sign(client_cert, root_key, EVP_sha256())) {
        perror("Failed to sign client certificate");
        X509_free(client_cert);
        EVP_PKEY_free(client_key);
        return NULL;
    }
    return client_cert;
}

// Set up SSL Context for the client connection
SSL_CTX *setup_ssl_context(X509 *client_cert, EVP_PKEY *client_key) {
    
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

    if (!SSL_CTX_use_certificate(ctx, client_cert)) {
        perror("Failed to use client certificate");
        return NULL;
    }

    if (!SSL_CTX_use_PrivateKey(ctx, client_key)) {
        perror("Failed to use client private key");
        return NULL;
    }

    return ctx;
}*/








