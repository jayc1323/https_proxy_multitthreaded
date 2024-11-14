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

#define SOCKET int
#define BUFFER_SIZE 4096
#define ISVALIDSOCKET(s) ((s) >= 0)
#define GETSOCKETERRNO() (errno)

// Open SSL Functions
void init_SSL(void);
void destroy_SSL(void);
void shutdown_SSL(void);

struct client_info {
    socklen_t address_length;
    struct sockaddr_storage address;
    SOCKET socket;
    char request[BUFFER_SIZE];
    int received;
    //char *file_requested;
};




// Server functions
SOCKET create_socket(const char *port);

