#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h> // work with x.509 certs
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>


#define SOCKET int
#define BUFFER_SIZE 4096
#define ISVALIDSOCKET(s) ((s) >= 0)
#define GETSOCKETERRNO() (errno)

struct client_info {
    socklen_t address_length;
    struct sockaddr_storage address;
    SOCKET socket;
    char request[BUFFER_SIZE];
    int received;
    //char *file_requested;
};

// Certificate management functions
EVP_PKEY *load_root_key(const char *key_path);
X509 *load_root_cert(const char *cert_path);
X509 *generate_client_cert(X509 *root_cert, EVP_PKEY *root_key, const char *hostname);
SSL_CTX *setup_ssl_context(X509 *client_cert, EVP_PKEY *client_key);

// OpenSSL Functions
void init_SSL(void);
void destroy_SSL(void);
void shutdown_SSL(SSL* cSSL);
int send_200(SOCKET new_client);
SOCKET connect_to_host(char *hostname, char *port) ;

// Server functions
SOCKET create_server_socket(const char *port);
void forward_request(char* buffer);

