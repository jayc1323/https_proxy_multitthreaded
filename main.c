#include "proxy.h"
// #include "cache.h"


int main (int argc, char* argv[]) {
    assert(argc == 2);
    const char* port_no = argv[1];

    SOCKET proxy_server = create_socket(port_no);

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
    sleep(5);
    close(new_client->socket);
    close(proxy_server);
    free(new_client);


    return 0;
}
