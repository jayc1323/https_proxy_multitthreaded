#include "proxy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/select.h>
#include <signal.h>
#include <omp.h>
#include <assert.h>

int main(int argc, char* argv[]){
         SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
         SOCKET proxy_server = create_server_socket(argv[1]);
    printf("Proxy server listening on port %s...\n", argv[1]);
      socklen_t address_length;
                    struct sockaddr_storage address;
                    SOCKET client_socket = accept(proxy_server, 
                                     (struct sockaddr*)&(address),
                                     &(address_length));

                    if (!ISVALIDSOCKET(client_socket)) {
                        fprintf(stderr, "accept() failed: %d\n", GETSOCKETERRNO());
                        
                        return 1;
                    }

                  
                    printf("Client connected (socket %d).\n", client_socket);
                    // char buffer[BUFFER_SIZE];
                    // int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
                    // if (bytes_received <= 0) {
                    //     fprintf(stderr, "Failed to receive data from client.\n");
                    //     close(client_socket);
                        
                    //     return 1;
                    // }
                    //  int s200 = send_200(client_socket);
                    //   buffer[bytes_received] = '\0'; // Null-terminate the request

                    // printf("Received client request:\n%s\n", buffer);

                    // // Parse the Host header
                    // char *host_header = strstr(buffer, "Host: ");
                    // if (!host_header) {
                    //     fprintf(stderr, "Missing Host header in request.\n");
                    //     close(client_socket);
                        
                    //     return 1;

                    // }

                    // host_header += 6; // Skip "Host: "
                    // char *end_of_host = strstr(host_header, "\r\n");
                    // if (end_of_host) *end_of_host = '\0';

                    // char *colon = strchr(host_header, ':');
                    // char port[6] = "443";
                    // if (colon) {
                    //     strncpy(port, colon + 1, sizeof(port) - 1);
                    //     *colon = '\0'; // Separate hostname from port
                    // }
                    
                    EVP_PKEY *root_key = load_root_key("private_key.pem");
                    assert(root_key!= NULL);
                    X509 *root_cert = load_root_cert("rootCA.crt");
                    assert(root_cert!= NULL);
                    EVP_PKEY *client_key = NULL;
                    X509 *client_cert = generate_client_cert(root_cert,root_key,"tuftscsproxy.com",&client_key);
                    assert(client_cert!=NULL);
                    assert(client_key!=NULL);
                    
                    SSL_CTX *context = setup_ssl_context(client_cert, client_key);
                    
                    SSL *ssl_client = SSL_new(context);
                    if (!ssl_client) {
                     
                        fprintf(stderr,"Failed SSL with client, disconnecting both endpoints\n");
                        return 1;
                    }

                SSL_set_fd(ssl_client, client_socket);  

                if (SSL_accept(ssl_client) <= 0) {
                    // Handle handshake error, use SSL_get_error() to get more details
                     SSL_free(ssl_client);
                     fprintf(stderr,"Failed SSL with client , disconnecting both endpoints\n");
                    
                     return 1;
                }
                fprintf(stderr,"SSL suceeded\n");
                //SSL_write(ssl_client,"Hello client!",14);
               
                    
                    fd_set readfds;
                    int max_sd = client_socket;
                    while(1){
                    FD_ZERO(&readfds);
                    FD_SET(client_socket,&readfds);
                    
                     int activity = select(max_sd+1,&readfds,NULL,NULL,NULL);
                     if(activity){
                        if(FD_ISSET(client_socket,&readfds)){
                            char buffer[4096];
                            int bytes_read = SSL_read(ssl_client,buffer,4096);
                            fprintf(stderr,"Message from client :\n %s",buffer);

                        }
                      
                     }

                    }
                   

                 SSL_shutdown(ssl_client);
                
    SSL_free(ssl_client);
    return 0;


}