#include "proxy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/select.h>
#include <signal.h>
#include <assert.h>
#include <omp.h>


#define BUFFER_SIZE 100000
#define MAX_CLIENTS 1000


int main1(char *port,  EVP_PKEY *root_key, X509 *root_cert);
int main2(char *port);
/*--------------------------------------------------------------------------------------------------------------------*/

int main(int argc,char *argv[]){
    signal(SIGPIPE, SIG_IGN);
    if(argc != 3){
        fprintf(stderr,"Usage : ./a.out port_no -ssl/tunnel");
        exit(1);
    }
    if (strcmp(argv[2],"-ssl")==0) {
          EVP_PKEY *root_key = load_root_key("private_key.pem");
        assert(root_key!= NULL);
        X509 *root_cert = load_root_cert("rootCA.crt");
        assert(root_cert!= NULL);
        return main1(argv[1],root_key,root_cert);
        
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
                if (i > max_sd) {
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
                      int s200 = send_200(client_socket);
                    if (s200 < 0){
                        close(client_socket);
                        //close(server_socket);
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
                    char buffer[BUFFER_SIZE];
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
int main1(char *port_no,  EVP_PKEY *root_key, X509 *root_cert){

     SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SOCKET proxy_server = create_server_socket(port_no);
    printf("Proxy server listening on port %s...\n", port_no);
    int max_sd = proxy_server;
    //TODO : INITIALIZE ENDPOINTS_ARRAY
    int *endpoints_array = malloc(MAX_CLIENTS * sizeof(int));
    assert(endpoints_array);
    SSL** ssl_array = malloc(MAX_CLIENTS * sizeof(SSL*));
    assert(ssl_array);

    //INITIALIZE
    for (int i = 0; i < MAX_CLIENTS; i++){
        endpoints_array[i] = -1;
        ssl_array[i] = NULL;
    }

    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(proxy_server,&readfds);
        max_sd = proxy_server;
       
        for(int i =0;i<MAX_CLIENTS;i++){
            if(endpoints_array[i]!=-1){

                FD_SET(i,&readfds);
                if(i>max_sd){
                    max_sd = i;
                }
            }
        }

        fprintf(stderr,"Waiting for a message/connection request\n");
        //CALL SELECT
        int activity = select(max_sd+1,&readfds,NULL,NULL,NULL);
        if (activity < 0) {
            fprintf(stderr, "select() error\n");
            break;
        }
       // omp_set_num_threads(6);
       // #pragma omp parallel for shared(max_sd,endpoints_array,ssl_array,readfds,proxy_server)
        for (SOCKET socket = 0; socket <= max_sd; socket++) {

            if (FD_ISSET(socket, &readfds)) {

                if (socket == proxy_server) {
                    fprintf(stderr,"Connection request at listening socket\n");
                    // LISTENING SOCKET IS READY : ACCEPT CONNECTION , DO A RECV TO READ CONNECT :
                    // CONNECT VIA SSL TO HOST , IF CONNECTED, SEND HTTP 200 TO CLIENT
                    // THEN DO SSL ACCEPT AT CLIENT , CONNECT CLIENT,SERVER IN ENDPOINTS ARRAY AND STORE THEIR SSL STRUCTS
                    
                  
                    struct sockaddr_storage address;
                      socklen_t address_length = sizeof(address);
                    SOCKET client_socket = accept(proxy_server, 
                                     (struct sockaddr*)&(address),
                                     &(address_length));

                    if (!ISVALIDSOCKET(client_socket)) {
                        fprintf(stderr, "accept() failed: %d\n", GETSOCKETERRNO());
                        
                        continue;
                    }
                     


                  
                    printf("Client connected (socket %d).\n", client_socket);
                    // set_nonblocking(client_socket);

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
                    send_200(client_socket);
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
                    
                    fprintf(stderr,"Building certificate\n");
                   
                    EVP_PKEY *client_key = NULL;
                    X509 *client_cert = generate_client_cert(root_cert,root_key,host_header,&client_key);
                    assert(client_cert!=NULL);
                    assert(client_key!=NULL);
                    
                    SSL_CTX *context = setup_ssl_context(client_cert, client_key);
                   SSL_CTX_set_alpn_protos(context, (unsigned char *)"\x08http/1.1\x02h2", 11);


                    
                    SSL *ssl_client = SSL_new(context);
                    if (!ssl_client) {
                        close(client_socket);
                       // close(server_socket);
                        fprintf(stderr,"Failed SSL with client, disconnecting both endpoints\n");
                        continue;
                    }

                SSL_set_fd(ssl_client, client_socket);  
                fprintf(stderr,"Trying to establish SSL with client\n");
                if (SSL_accept(ssl_client) <= 0) {
                    // Handle handshake error, use SSL_get_error() to get more details
                     SSL_free(ssl_client);
                     fprintf(stderr,"Failed SSL with client , disconnecting both endpoints\n");
                     close(client_socket);
                    // close(server_socket);
                     continue;
                
                }
                fprintf(stderr,"SSL with client established\n");

                    // Parse the Host header
                  

                    printf("Connecting to server %s on port %s...\n", host_header, port);

                    // Connect to the target server
                    SOCKET server_socket = connect_to_host(host_header, port);
                    if (!ISVALIDSOCKET(server_socket)) {
                        fprintf(stderr, "Failed to connect to server %s:%s\n", host_header, port);
                        close(client_socket);
                       
                        continue;
                    }
                    // set_nonblocking(server_socket);
                    
                    SSL* server_ssl = ssl_with_server(server_socket);
                    if(server_ssl == NULL) {
                        fprintf(stderr,"SSL Handshake with server failed\n");
                        close(client_socket);
                        close(server_socket);
                        continue;
                    }
                    //SEND HTTP 200 TO CLIENT
                   
                    // Establish SSL WITH CLIENT
                   
              //  FD_SET(client_socket,&readfds);
               // FD_SET(server_socket,&readfds);
            //    int a = set_nonblocking(server_socket);
            //    int b = set_nonblocking(client_socket);
            //    assert(a==0);
            //    assert(b==0);
            //    SSL_set_mode(ssl_client, SSL_MODE_ASYNC);
            //    SSL_set_mode(server_ssl,SSL_MODE_ASYNC);

                endpoints_array[client_socket] = server_socket;
                endpoints_array[server_socket] = client_socket;
                ssl_array[client_socket] = ssl_client;
                ssl_array[server_socket] = server_ssl;

            } else {
                //READ FROM SOCKET 
                fprintf(stderr,"New message from client :%d\n",socket);
                SSL* sender = ssl_array[socket];
                SOCKET recver = endpoints_array[socket];
                fprintf(stderr,"Receiver of this message is : %d\n",recver);
                SSL* receiver = ssl_array[recver];
                if(sender == NULL || receiver==NULL){
                    continue;
                }
                

                
                assert(sender!=NULL);
                assert(receiver!=NULL);
                 
                 
                    char buffer[BUFFER_SIZE];
               fprintf(stderr,"Calling SSL read on client with socket no %d\n",socket);  
               int bytes_read = SSL_read(sender,buffer,BUFFER_SIZE);
               fprintf(stderr,"bytes read from SSL_read is %d\n",bytes_read);  
              
               
             
                 
                if (bytes_read<=0) {
                    //ERROR HANDLING
                    //   SSL_shutdown(sender);
                    //   SSL_shutdown(receiver);
                    // SSL_free(sender);
                    // SSL_free(receiver);
                  
                    // FD_CLR(socket,&readfds);
                    // FD_CLR(recver,&readfds);
                    // close(socket);
                    // close(recver);
                    // endpoints_array[socket] = -1;
                    // endpoints_array[recver] = -1;
                    // ssl_array[socket] = NULL;
                    // ssl_array[recver] = NULL;
                    continue;
                }
                    fprintf(stderr,"Data received from SSL_Read :\n%s\n",buffer);
                    int bytes_sent = SSL_write(receiver,buffer,bytes_read);
                 fprintf(stderr,"bytes sent using SSL write is %d\n",bytes_sent);  

               
                
                if (bytes_sent <= 0) {
                    //ERROR HANDLING
                    //  SSL_shutdown(sender);
                    //   SSL_shutdown(receiver);
                    // SSL_free(sender);
                    // SSL_free(receiver);
                    // FD_CLR(socket,&readfds);
                    // FD_CLR(recver,&readfds);
                    // close(socket);
                    // close(recver);
                    // endpoints_array[socket] = -1;
                    // endpoints_array[recver] = -1;
                    // ssl_array[socket] = NULL;
                    // ssl_array[recver] = NULL;
                    continue;
                }

            }

            }
        }
      
    }
      free(endpoints_array);
      free(ssl_array);
    
      return 0;
        
    
}
// int main1(char *port_no, EVP_PKEY *root_key, X509 *root_cert) {
//     SOCKET proxy_server = create_server_socket(port_no);
//     printf("Proxy server listening on port %s...\n", port_no);

//     // Allocate and initialize data structures
//     struct pollfd poll_fds[MAX_CLIENTS];
//     int endpoints_array[MAX_CLIENTS];
//     SSL *ssl_array[MAX_CLIENTS] = {0};
    
//     for (int i = 0; i < MAX_CLIENTS; i++) {
//         poll_fds[i].fd = -1;  // Initialize all file descriptors as unused
//         poll_fds[i].events = 0;
//         endpoints_array[i] = -1;
//     }

//     poll_fds[0].fd = proxy_server;  // Add the listening socket
//     poll_fds[0].events = POLLIN;

//     while (1) {
//         fprintf(stderr, "Waiting for a message/connection request\n");

//         int activity = poll(poll_fds, MAX_CLIENTS, -1);  // Wait indefinitely
//         if (activity < 0) {
//             fprintf(stderr, "poll() error\n");
//             break;
//         }

//         for (int i = 0; i < MAX_CLIENTS; i++) {
//             if (poll_fds[i].fd == -1) continue;

//             if (poll_fds[i].revents & POLLIN) {
//                 if (poll_fds[i].fd == proxy_server) {
//                     // Handle new incoming connection
//                     fprintf(stderr, "Connection request at listening socket\n");

//                     struct sockaddr_storage address;
//                     socklen_t address_length = sizeof(address);
//                     SOCKET client_socket = accept(proxy_server, 
//                                                   (struct sockaddr *)&address, 
//                                                   &address_length);
//                     if (!ISVALIDSOCKET(client_socket)) {
//                         fprintf(stderr, "accept() failed: %d\n", GETSOCKETERRNO());
//                         continue;
//                     }

//                     printf("Client connected (socket %d).\n", client_socket);

//                     // Add the client socket to poll_fds
                  
//                     poll_fds[client_socket].fd = client_socket;
//                     poll_fds[client_socket].events = POLLIN;



//                     // Receive client request
//                     char buffer[BUFFER_SIZE];
//                     int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
//                     if (bytes_received <= 0) {
//                         fprintf(stderr, "Failed to receive data from client.\n");
//                         close(client_socket);
//                         continue;
//                     }
//                     buffer[bytes_received] = '\0';  // Null-terminate the request
//                     printf("Received client request:\n%s\n", buffer);

//                     send_200(client_socket);

//                     // Extract Host header
//                     char *host_header = strstr(buffer, "Host: ");
//                     if (!host_header) {
//                         fprintf(stderr, "Missing Host header in request.\n");
//                         close(client_socket);
//                         continue;
//                     }

//                     host_header += 6;  // Skip "Host: "
//                     char *end_of_host = strstr(host_header, "\r\n");
//                     if (end_of_host) *end_of_host = '\0';

//                     char *colon = strchr(host_header, ':');
//                     char port[6] = "443";
//                     if (colon) {
//                         strncpy(port, colon + 1, sizeof(port) - 1);
//                         *colon = '\0';  // Separate hostname from port
//                     }

//                     fprintf(stderr, "Building certificate\n");

//                     EVP_PKEY *client_key = NULL;
//                     X509 *client_cert = generate_client_cert(root_cert, root_key, host_header, &client_key);
//                     assert(client_cert != NULL);
//                     assert(client_key != NULL);

//                     SSL_CTX *context = setup_ssl_context(client_cert, client_key);
//                     SSL *ssl_client = SSL_new(context);
//                     if (!ssl_client) {
//                         close(client_socket);
//                         fprintf(stderr, "Failed SSL with client, disconnecting both endpoints\n");
//                         continue;
//                     }

//                     SSL_set_fd(ssl_client, client_socket);
//                     fprintf(stderr, "Trying to establish SSL with client\n");
//                     if (SSL_accept(ssl_client) <= 0) {
//                         SSL_free(ssl_client);
//                         fprintf(stderr, "Failed SSL with client, disconnecting both endpoints\n");
//                         close(client_socket);
//                         continue;
//                     }
//                     fprintf(stderr, "SSL with client established\n");

//                     // Connect to the target server
//                     SOCKET server_socket = connect_to_host(host_header, port);
//                     if (!ISVALIDSOCKET(server_socket)) {
//                         fprintf(stderr, "Failed to connect to server %s:%s\n", host_header, port);
//                         close(client_socket);
//                         continue;
//                     }

//                     SSL *server_ssl = ssl_with_server(server_socket);
//                     if (server_ssl == NULL) {
//                         fprintf(stderr, "SSL Handshake with server failed\n");
//                         close(client_socket);
//                         close(server_socket);
//                         continue;
//                     }

//                     // Update poll_fds and endpoints_array
                    
                        
//                             poll_fds[server_socket].fd = server_socket;
//                             poll_fds[server_socket].events = POLLIN;  // Monitor for incoming data
//                             endpoints_array[client_socket] = server_socket;
//                             endpoints_array[server_socket] = client_socket;
//                             ssl_array[client_socket] = ssl_client;
//                             ssl_array[server_socket] = server_ssl;
                            
                        
                    

//                 } else {
//                     // Handle data from existing connection
//                     fprintf(stderr, "New message from socket %d\n", poll_fds[i].fd);

//                     SOCKET socket = poll_fds[i].fd;
//                     SSL *sender = ssl_array[socket];
//                     SOCKET receiver_socket = endpoints_array[socket];
//                     SSL *receiver = ssl_array[receiver_socket];

//                     char buffer[BUFFER_SIZE];
//                     assert(sender != NULL);
//                     assert(receiver != NULL);

//                     int bytes_read = SSL_read(sender, buffer, BUFFER_SIZE);
//                     if (bytes_read <= 0) {
//                         // Handle disconnection or error
//                         SSL_shutdown(sender);
//                         SSL_shutdown(receiver);
//                         SSL_free(sender);
//                         SSL_free(receiver);
//                         close(socket);
//                         close(receiver_socket);

//                         poll_fds[i].fd = -1;
//                         for (int k = 0; k < MAX_CLIENTS; k++) {
//                             if (poll_fds[k].fd == receiver_socket) {
//                                 poll_fds[k].fd = -1;
//                                 break;
//                             }
//                         }

//                         endpoints_array[socket] = -1;
//                         endpoints_array[receiver_socket] = -1;
//                         ssl_array[socket] = NULL;
//                         ssl_array[receiver_socket] = NULL;
//                         continue;
//                     }

//                     int bytes_sent = SSL_write(receiver, buffer, bytes_read);
//                     if (bytes_sent <= 0) {
//                         // Handle error in sending
//                         SSL_shutdown(sender);
//                         SSL_shutdown(receiver);
//                         SSL_free(sender);
//                         SSL_free(receiver);
//                         close(socket);
//                         close(receiver_socket);

//                         poll_fds[i].fd = -1;
//                         for (int k = 0; k < MAX_CLIENTS; k++) {
//                             if (poll_fds[k].fd == receiver_socket) {
//                                 poll_fds[k].fd = -1;
//                                 break;
//                             }
//                         }

//                         endpoints_array[socket] = -1;
//                         endpoints_array[receiver_socket] = -1;
//                         ssl_array[socket] = NULL;
//                         ssl_array[receiver_socket] = NULL;
//                         continue;
//                     }
//                 }
//             }
//         }
//     }

//     return 0;
// }
