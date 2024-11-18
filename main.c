#include "proxy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/select.h>

#define BUFFER_SIZE 4096
#define MAX_CLIENTS 100000

int main1(char *port);
int main2(char *port);
/*--------------------------------------------------------------------------------------------------------------------*/

int main(int argc,char *argv[]){
    if(argc != 3){
        fprintf(stderr,"Usage : ./a.out port_no -ssl/tunnel");
        exit(1);
    }
    if (strcmp(argv[2],"-ssl")==0) {
        return main1(argv[1]);
    }
    else if (strcmp(argv[2],"-tunnel")==0) {
        return main2(argv[1]);
    } else {
        fprintf(stderr,"Usage : ./a.out port_no -ssl/tunnel");
        exit(1);
         
    }
    
}
/*----------------------------------------------------------------------------------------------------------------------------------------------*/



/*-----------------------------------------------------------------------------------------------------------------------------------*/
int main2(char *port_no) {

    int *endpoints_array = malloc(MAX_CLIENTS * sizeof(int));
    // Create server socket
    SOCKET proxy_server = create_server_socket(port_no);

    printf("Proxy server listening on port %s...\n", port_no);
    for (int i = 0; i < MAX_CLIENTS; i++){
        endpoints_array[i] = -1;
    }
   

    while (1) {
        fd_set readfds; 
        FD_ZERO(&readfds);
        FD_SET(proxy_server, &readfds);
            

        int max_sd = proxy_server;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (endpoints_array[i] != -1) {
                FD_SET(i, &readfds);
                if(i > max_sd) {
                    max_sd = i;
                }
            }
        }


        fprintf(stderr,"Waiting for message or connection request\n");    
        
        int activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        if (activity < 0) {
            fprintf(stderr, "select() error\n");
            break;
        }

        for (SOCKET socket = 0; socket <= max_sd; socket++) {
            if(FD_ISSET(socket, &readfds)) {
                if (socket == proxy_server) {
            /*IF THERE IS A CONNECTION REQUEST TO THE LISTENING SOCKET
               , ACCEPT CONNECTION , READ THE REQUEST , CONNECT TO SERVER ,
               IF SUCCESSFUL , ADD BOTH CLIENT AND SERVER SOCKET TO READ_FDS
               AND HAVE A MAPPING FROM CLIENT->SERVER AND SERVER->CLIENT
               TO KNOW WHERE TO SEND FUTURE MESSAGES
            */
                    socklen_t address_length;
                    struct sockaddr_storage address;
                    SOCKET client_socket = accept(proxy_server, 
                                     (struct sockaddr*)&(address),
                                     &(address_length));

                    if (!ISVALIDSOCKET(client_socket)) {
                        fprintf(stderr, "accept() failed: %d\n", GETSOCKETERRNO());
                        
                        continue;
                    }

                  
                    printf("Client connected (socket %d).\n", client_socket);

                    // Receive client request
                    char buffer[BUFFER_SIZE];
                    int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
                    if (bytes_received <= 0) {
                        fprintf(stderr, "Failed to receive data from client.\n");
                        close(client_socket);
                        
                        continue;
                    }
                    buffer[bytes_received] = '\0'; // Null-terminate the request

                    printf("Received client request:\n%s\n", buffer);

                    // Parse the Host header
                    char *host_header = strstr(buffer, "Host: ");
                    if (!host_header) {
                        fprintf(stderr, "Missing Host header in request.\n");
                        close(client_socket);
                        
                        continue;

                    }

                    host_header += 6; // Skip "Host: "
                    char *end_of_host = strstr(host_header, "\r\n");
                    if (end_of_host) *end_of_host = '\0';

                    char *colon = strchr(host_header, ':');
                    char port[6] = "443";
                    if (colon) {
                        strncpy(port, colon + 1, sizeof(port) - 1);
                        *colon = '\0'; // Separate hostname from port
                    }

                    printf("Connecting to server %s on port %s...\n", host_header, port);

                    // Connect to the target server
                    SOCKET server_socket = connect_to_host(host_header, port);
                    if (!ISVALIDSOCKET(server_socket)) {
                        fprintf(stderr, "Failed to connect to server %s:%s\n", host_header, port);
                        close(client_socket);
                       
                        continue;
                    }
                    int s200 = send_200(client_socket);
                    if(s200<0){
                        close(client_socket);
                        close(server_socket);
                        continue;
                    }

                    // Send HTTP 200 to client
                    FD_SET(client_socket, &readfds);
                    FD_SET(server_socket, &readfds);
                    if(client_socket>max_sd){
                        max_sd = client_socket;
                    }
                    if(server_socket>max_sd){
                        max_sd = server_socket;
                    }

                    endpoints_array[client_socket] = server_socket;
                    endpoints_array[server_socket] = client_socket;
                    
                
                } else {
                    //DETERMINE THE OTHER END POINT FOR THIS SOCKET
                    //SEND MESSAGE
                    char buffer[4096];
                    int bytes_recv = recv(socket,buffer,4096,0);
        
                    if (bytes_recv <= 0) {
                        // fprintf(stderr, "Client or server disconnected.\n");
                        // fprintf(stderr,"Also disconnecting other endpoint\n");
                        close(socket);
                        close(endpoints_array[socket]);
                        FD_CLR(socket,&readfds);
                        FD_CLR(endpoints_array[socket],&readfds);
                        int s = endpoints_array[socket];
                        endpoints_array[socket] = -1;
                        endpoints_array[s] = -1;
                        
                        continue;
                    }
                    // printf("Received message from one endpoint\n");
                    int bytes_sent = send(endpoints_array[socket], buffer, bytes_recv, 0);
        
                    if (bytes_sent <= 0) {
                        // fprintf(stderr, "Client or server disconnected.\n");
                        // fprintf(stderr, "Also disconnecting other endpoint\n");
                        close(socket);
                        close(endpoints_array[socket]);
                        FD_CLR(socket, &readfds);
                        FD_CLR(endpoints_array[socket], &readfds);
                          int s = endpoints_array[socket];
                        endpoints_array[socket] = -1;
                        endpoints_array[s] = -1;
                        continue;
                    }
                    // printf("Message from client/server send to other endpoint\n");
                }
            }
        }
    }
    close(proxy_server);
    free(endpoints_array);
    return 0;
}
/*-----------------------------------------------------------------------------------------------------------------------------------------*/
int main1(char *port_no){
    (void)port_no;
    return 0;
}
//     assert(argc == 2);
//     const char* port_no = argv[1];

//     // Create socket
//     SOCKET proxy_server = create_server_socket(port_no);

//     // Initialize SSL framework
//     init_SSL();

//     struct client_info *new_client = calloc(1, sizeof(*new_client));
//     assert(new_client != NULL);

//     SOCKET client_socket = accept(proxy_server, 
//                                  (struct sockaddr*)&(new_client->address),
//                                  &(new_client->address_length));
    
//     if (!ISVALIDSOCKET(client_socket)) {
//         fprintf(stderr, "accept() failed: %d\n", GETSOCKETERRNO());
//         free(new_client);
//         return 1;
//     } else {
//         printf("%d\n", client_socket);
//     }

//     new_client->socket = client_socket;

//     int bytes_recvd = recv(new_client->socket,
//                            new_client->request, BUFFER_SIZE, 0);
//     if (bytes_recvd < 0) { 
//         fprintf(stderr, "Bytes_read < 0\n");
//         free(new_client);
//         exit(1);
//     }
    

//     fprintf(stderr, "Received request successfully\n");
//     new_client->request[bytes_recvd] = '\0';

//     //printf("Hello world\n");
//     printf("Client request: %s\n", new_client->request);
//      sleep(5);
//     // Send 200 message to ack connection
//     send_200(new_client);

    
//     while(1){// Init SSL for client
//     SSL_CTX* sslctx = SSL_CTX_new(SSLv23_server_method());
//     SSL* ssl = SSL_new(sslctx);
//     SSL_set_fd(ssl, new_client->socket);

//     SSL_use_certificate_file(ssl, "server_cert.pem", SSL_FILETYPE_PEM);
//     SSL_use_PrivateKey_file(ssl, "server_key.pem", SSL_FILETYPE_PEM);
//     SSL_accept(ssl);


//     // Read bytes from encrypted connection
//     char buffer[BUFFER_SIZE];
//     printf("Now reading from SSL_read\n");
//     SSL_read(ssl, buffer, BUFFER_SIZE - 1);
//     buffer[BUFFER_SIZE - 1] = '\0';
//     printf("Buffer from SSL_read:\n%s\n", buffer);
    
//     char* response = 
//         "HTTP/1.1 200 OK\r\n"
//         "Content-Type: text/plain/r/n"
//         "Content-Length: 13\r\n"
//         "\r\n"
//         "Hello, world\0";
//     SSL_write(ssl, response, strlen(response));
//     }

//     // Foward client request to server
//     void forward_request(char* buffer);



//     close(new_client->socket);
//     close(proxy_server);
//     free(new_client);


//     return 0;
