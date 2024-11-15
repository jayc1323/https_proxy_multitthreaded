#include "proxy.h"

// Globals
// SSL_CTX* sslctx; // SSL framework object
// SSL* cSSL; // SSL connection (?)


int main (int argc, char* argv[]) {
    assert(argc == 2);
    const char* port_no = argv[1];

    // Create socket
    SOCKET proxy_server = create_server_socket(port_no);

    // Initialize SSL framework
    init_SSL();

    struct client_info *new_client = calloc(1, sizeof(*new_client));
    assert(new_client != NULL);

    SOCKET client_socket = accept(proxy_server, 
                                 (struct sockaddr*)&(new_client->address),
                                 &(new_client->address_length));
    
    if (!ISVALIDSOCKET(client_socket)) {
        fprintf(stderr, "accept() failed: %d\n", GETSOCKETERRNO());
        free(new_client);
        return 1;
    } else {
        printf("%d\n", client_socket);
    }

    new_client->socket = client_socket;

    int bytes_recvd = recv(new_client->socket,
                           new_client->request, BUFFER_SIZE, 0);
    if (bytes_recvd < 0) { 
        fprintf(stderr, "Bytes_read < 0\n");
        free(new_client);
        exit(1);
    }

    fprintf(stderr, "Received request successfully\n");
    new_client->request[bytes_recvd] = '\0';

    printf("Hello world\n");
    printf("Client request: %s\n", new_client->request);
    // sleep(5);
    // Send 200 message to ack connection
    send_200(new_client);

    // Init SSL for client
    SSL_CTX* sslctx = SSL_CTX_new(SSLv23_server_method());
    SSL* ssl = SSL_new(sslctx);
    SSL_set_fd(ssl, new_client->socket);

    SSL_use_certificate_file(ssl, "server_cert.pem", SSL_FILETYPE_PEM);
    SSL_use_PrivateKey_file(ssl, "server_key.pem", SSL_FILETYPE_PEM);
    SSL_accept(ssl);


    // Read bytes from encrypted connection
    char buffer[BUFFER_SIZE];
    printf("Now reading from SSL_read\n");
    SSL_read(ssl, buffer, BUFFER_SIZE - 1);
    buffer[BUFFER_SIZE - 1] = '\0';
    printf("Buffer from SSL_read:\n%s\n", buffer);
    
    char* response = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain/r/n"
        "Content-Length: 13\r\n"
        "\r\n"
        "Hello, world\0";
    SSL_write(ssl, response, strlen(response));

    // Foward client request to server
    void forward_request(char* buffer);



    close(new_client->socket);
    close(proxy_server);
    free(new_client);


    return 0;
}
