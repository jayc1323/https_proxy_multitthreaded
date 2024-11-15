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

void send_200(struct client_info* client) {
    const char* c200 = "HTTP/1.1 200 Connection Established\r\n\r\n";
    int bytes_writ = send(client->socket, c200, strlen(c200), 0);
    if (bytes_writ < 0) {
        fprintf(stderr, "Error sending 200 message to client\n");
        exit(1);
    }
    printf("200 message successfully sent\n");
}

void forward_request(char* buffer) {
    printf("placeholder\n");
}
