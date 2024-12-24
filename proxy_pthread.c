#include "proxy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/select.h>
#include <signal.h>
#include <assert.h>
// #include <omp.h>
#include <ctype.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>     
#include <stdbool.h>
#include <curl/curl.h>
#include "cJSON.h"
#define BUFFER_SIZE 100000
#define MAX_CLIENTS 1000
#define NUM_THREADS 3
#define RESPONSE_SIZE 100000
#define MAX_BUFFER_SIZE 4096
// dont change
const char *url = "https://a061igc186.execute-api.us-east-1.amazonaws.com/dev";

// API key
const char *x_api_key = "x-api-key: comp11286nkWwDMdwZAmd53zUetwlbhvWiKxTclwqhC1Ppl"; 



void send_file_response(SSL *ssl_client, const char *file_path) {
    // Open the file
    int file_fd = open(file_path, O_RDONLY);
    if (file_fd < 0) {
        perror("Failed to open file");
        const char *error_response =
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n\r\n";
        SSL_write(ssl_client, error_response, strlen(error_response));
        return;
    }

    // Get the file size
    struct stat file_stat;
    if (fstat(file_fd, &file_stat) < 0) {
        perror("Failed to get file stats");
        close(file_fd);
        const char *error_response =
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n\r\n";
        SSL_write(ssl_client, error_response, strlen(error_response));
        return;
    }
    size_t file_size = file_stat.st_size;

    // Create HTTP response header
    char http_header[BUFFER_SIZE];
    snprintf(http_header, sizeof(http_header),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: text/html\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n\r\n",
             file_size);

    // Send HTTP header
    if (SSL_write(ssl_client, http_header, strlen(http_header)) <= 0) {
        perror("Failed to send HTTP header");
        close(file_fd);
        return;
    }

    // Send file content
    char file_buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    while ((bytes_read = read(file_fd, file_buffer, sizeof(file_buffer))) > 0) {
        if (SSL_write(ssl_client, file_buffer, bytes_read) <= 0) {
            perror("Failed to send file content");
            break;
        }
    }

    // Clean up
    close(file_fd);
}
/*-------------------------------------------------------------------------------------------------------------------------------------*/
void send_file_response2(SSL *ssl_client, const char *file_path) {
    // Open the file
    int file_fd = open(file_path, O_RDONLY);
    if (file_fd < 0) {
        perror("Failed to open file");
        const char *error_response =
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n\r\n";
        SSL_write(ssl_client, error_response, strlen(error_response));
        return;
    }

    // Get the file size
    struct stat file_stat;
    if (fstat(file_fd, &file_stat) < 0) {
        perror("Failed to get file stats");
        close(file_fd);
        const char *error_response =
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Type: application/json\r\n"
            
            "Connection: close\r\n\r\n";
        SSL_write(ssl_client, error_response, strlen(error_response));
        return;
    }
    size_t file_size = file_stat.st_size;

    // Create HTTP response header
    char http_header[BUFFER_SIZE];
    snprintf(http_header, sizeof(http_header),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: application/javascript\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n\r\n",
             file_size);

    // Send HTTP header
    if (SSL_write(ssl_client, http_header, strlen(http_header)) <= 0) {
        perror("Failed to send HTTP header");
        close(file_fd);
        return;
    }

    // Send file content
    char file_buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    while ((bytes_read = read(file_fd, file_buffer, sizeof(file_buffer))) > 0) {
        if (SSL_write(ssl_client, file_buffer, bytes_read) <= 0) {
            perror("Failed to send file content");
            break;
        }
    }

    // Clean up
    close(file_fd);
}
/*-----------------------------------------------------------------------------------------------------------------------------------------------------------*/

void cleanup(SOCKET client_socket, SOCKET server_socket, SSL *ssl_client, SSL *server_ssl);
void parse_json_payload(const char *buffer, char *prompt, char *lastk, char *temperature,char* system);
void execute_threads(char *prompt, double temperature, int lastk,char* system,
                     char *gpt4_response, char *claude_response, char *phi_response);
void *llmproxy_request(void *arg);
void send_json_response(SSL *client_socket, char *gpt4_response, 
                        char *claude_response, char *phi_response);
char *sanitize_json(const char *input);

/*----------------------------------------------------------------------------*/
// Connection struct to manage clients, keys, certs
typedef struct Connection{
        SOCKET client;
        char request_buffer[1000];
        EVP_PKEY *root_key;
        X509 *root_cert;
} *Connection;

// Struct to pass params to threads for API call

typedef struct ThreadData {
    char* model;
    char* system;
    char* prompt;
    double temp;
    int lastK;
    char* response; // store result
} *ThreadData;


/*-------------------------------------------------------------------------------------------------*/

void *fetch_llm_response(void *arg) {
    ThreadData data = (ThreadData)arg;

    // Sim API call 
    printf("Fetching response for prompt: %s\n", data->response);
    // Ex: Call the respective LLM API and store result
    sprintf(data->response, "Mock response from LLM for prompt: %s", data->response);

    return NULL;
}

/*-----------------------------------------------------------------------------------------*/

/*-
***PURPOSE:THIS FUNCTION IS EXECUTED BY EACH THREAD WHEN THE THREAD 
            CALLING IT IS CREATED.
            IT DYNAMICALLY GENERATES A DOMAIN SPECIFIC CERTIFICATE AND MANAGES DATA TRANSMISSION
            BETWEEN THE ACTUAL SERVER AND THE CLIENT.
            DOES NOT BLOCK THE MAIN THREAD AND THE LISTENING SOCKET FROM ACCEPTING NEW CONNECTIONS.
   ARGUMENTS: A VOID POINTER TO A CONNECTION STRUCT.


*/
void* thread_function(void* arg) {
    Connection conn = (Connection)arg; 

    // Extract socket descriptors
         SOCKET client_socket = conn->client;
        EVP_PKEY *root_key = conn->root_key;
        X509 *root_cert = conn->root_cert;
        char* buffer = conn->request_buffer;
           char *host_header = strstr(buffer, "Host: ");
                    if (!host_header) {
                        fprintf(stderr, "Missing Host header in request.\n");
                        close(client_socket);
                        return NULL;
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
                        return NULL;
                    }

                SSL_set_fd(ssl_client, client_socket);  
                fprintf(stderr,"Trying to establish SSL with client\n");
                if (SSL_accept(ssl_client) <= 0) {
                    // Handle handshake error, use SSL_get_error() to get more details
                     SSL_free(ssl_client);
                     fprintf(stderr,"Failed SSL with client , disconnecting both endpoints\n");
                     close(client_socket);
                    // close(server_socket);
                          return NULL;
                
                }
                fprintf(stderr,"SSL with client established\n");

                    // Parse the Host header
                  

                    printf("Connecting to server %s on port %s...\n", host_header, "443");

                    // Connect to the target server
                    SOCKET server_socket = connect_to_host(host_header, "443");
                    if (!ISVALIDSOCKET(server_socket)) {
                        fprintf(stderr, "Failed to connect to server %s:%s\n", host_header, "443");
                        close(client_socket);
                       
                        return NULL;
                    }
                    // set_nonblocking(server_socket);
                    
                    SSL* server_ssl = ssl_with_server(server_socket);
                    if(server_ssl == NULL) {
                        fprintf(stderr,"SSL Handshake with server failed\n");
                        close(client_socket);
                        close(server_socket);
                     return NULL;
                    }
   

    fd_set readfds;
    

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(client_socket, &readfds);
        FD_SET(server_socket, &readfds);

        SOCKET max_sd = (client_socket > server_socket) ? client_socket : server_socket;

        int activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        if (activity < 0) {
            perror("select failed");
            break;
        }

        // Check client socket
        if (FD_ISSET(client_socket, &readfds)) {

            char buffer[BUFFER_SIZE];    
            int bytes_read = SSL_read(ssl_client, buffer, sizeof(buffer));
            if (bytes_read <= 0) {
                
                  close(client_socket);
                 close(server_socket);
                 SSL_shutdown(ssl_client);
                 SSL_shutdown(server_ssl);
                 SSL_free(ssl_client);
                 SSL_free(server_ssl);
                 free(conn);
                 return NULL;
            }
            printf("%s\n",buffer);
            int bytes_sent = SSL_write(server_ssl,buffer,bytes_read);
            if(bytes_sent<=0){
                //TODO
                    close(client_socket);
                 close(server_socket);
                 SSL_shutdown(ssl_client);
                 SSL_shutdown(server_ssl);
                 SSL_free(ssl_client);
                 SSL_free(server_ssl);
                 free(conn);
                 return NULL;
            }
           
        }

        // Check server socket
        if (FD_ISSET(server_socket, &readfds)) {
            char buffer[BUFFER_SIZE];    
            int bytes_read = SSL_read(server_ssl, buffer, sizeof(buffer));
            if (bytes_read <= 0) {
                //TODO
                 close(client_socket);
                 close(server_socket);
                 SSL_shutdown(ssl_client);
                 SSL_shutdown(server_ssl);
                 SSL_free(ssl_client);
                 SSL_free(server_ssl);
                 free(conn);
                 return NULL;
            }
            int bytes_sent = SSL_write(ssl_client,buffer,bytes_read);
            if(bytes_sent<=0){
                //TODO
                   close(client_socket);
                 close(server_socket);
                 SSL_shutdown(ssl_client);
                 SSL_shutdown(server_ssl);
                 SSL_free(ssl_client);
                 SSL_free(server_ssl);
                 free(conn);
                 return NULL;
            }
        }

    }
    return NULL;

    // Clean up resources
    
}
/*--------------------------------------------------------------------------------------------------------------------------------------------------------*/

void* thread_function2(void* arg) {
    Connection conn = (Connection)arg; 

    // Extract socket descriptors
    SOCKET client_socket = conn->client;
    EVP_PKEY *root_key = conn->root_key;
    X509 *root_cert = conn->root_cert;
    char* buffer = conn->request_buffer;
    char *host_header = strstr(buffer, "Host: ");
    if (!host_header) {
        fprintf(stderr, "Missing Host header in request.\n");
        close(client_socket);
        return NULL;
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
        return NULL;
    }

    SSL_set_fd(ssl_client, client_socket);  
    fprintf(stderr,"Trying to establish SSL with client\n");
    if (SSL_accept(ssl_client) <= 0) {
        // Handle handshake error, use SSL_get_error() to get more details
            SSL_free(ssl_client);
            fprintf(stderr,"Failed SSL with client , disconnecting both endpoints\n");
            close(client_socket);
        // close(server_socket);
                return NULL;
    
    }
    fprintf(stderr,"SSL with client established\n");

    fd_set readfds;
    
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(client_socket, &readfds);

        SOCKET max_sd = client_socket;

        int activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        if (activity < 0) {
            perror("select failed");
            break;
        }

        // Check client socket
        if (FD_ISSET(client_socket, &readfds)) {
            char request_buffer[BUFFER_SIZE];
            int bytes_read = SSL_read(ssl_client,request_buffer,BUFFER_SIZE);
            if (bytes_read <= 0) {
                break;
            }
            // Request made to ChatGPT webpage
            if (strstr(request_buffer, "GET / ")) {
                send_file_response(ssl_client, "index.html");
                // User clicked Generate button
            } else if (strstr(request_buffer, 
                       "POST /generate-response") != NULL) {
                // Parse incoming payload
                printf("REQUEST BUFFER:\n%s\n", request_buffer);
                char prompt[512], lastk[10], temp[10],system[512];
                parse_json_payload(request_buffer, prompt, lastk, temp,system);

                // Call thraed function to get responses
                char gpt4_response[4096] = {0};
                char claude_response[4096] = {0};
                char phi_response[4096] = {0};

                execute_threads(prompt, atof(temp), atoi(lastk),system, gpt4_response, claude_response, phi_response);
                printf("Response LLM1 :%s\n",gpt4_response);
                printf("Response LLM2 :%s\n",claude_response);
                printf("Response LLM3 :%s\n",phi_response);

                send_json_response(ssl_client, gpt4_response, claude_response, phi_response);

            }
        }
    }
    return NULL;
}    

/*---------------------------------------------------------------------------------------*/
void execute_threads(char *prompt, double temperature, int lastk,char* system,
                     char *gpt4_response, char *claude_response, char *phi_response) {
    pthread_t threads[3];
    ThreadData data[3];
    char *models[3] = {"4o-mini", "anthropic.claude-3-haiku-20240307-v1:0", "azure-phi3"};
    char *responses[3] = {gpt4_response, claude_response, phi_response};

    // Prepare thread data for each LLM
    for (int i = 0; i < 3; i++) {
        data[i] = (ThreadData)malloc(sizeof(struct ThreadData));
        if (data[i] == NULL) {
            fprintf(stderr, "Memory allocation failed for ThreadData[%d]\n", i);
            exit(EXIT_FAILURE);
        }
        data[i]->system = system;
        data[i]->model = models[i];
        data[i]->prompt = prompt;
        data[i]->temp = temperature;
        data[i]->lastK = lastk;
        data[i]->response = responses[i];
    }

    // Create threads
    for (int i = 0; i < 3; i++) {
        if (pthread_create(&threads[i], NULL, llmproxy_request, data[i]) != 0) {
            fprintf(stderr, "Error creating thread %d\n", i);
            exit(EXIT_FAILURE);
        }
    }

    // Join threads
    for (int i = 0; i < 3; i++) {
        pthread_join(threads[i], NULL);
        free(data[i]); // Free allocated memory for each ThreadData
    }
}
void execute_threads2(char *prompt, double temperature, int lastk, char *system, char *gpt4_response) {
    pthread_t thread;
    ThreadData data = (ThreadData )malloc(sizeof(struct ThreadData));
    if (data == NULL) {
        fprintf(stderr, "Memory allocation failed for ThreadData\n");
        exit(EXIT_FAILURE);
    }
    
    // Prepare thread data for gpt4
    data->system = system;
    data->model = "4o-mini"; // gpt4 model identifier
    data->prompt = prompt;
    data->temp = temperature;
    data->lastK = lastk;
    data->response = gpt4_response;

    fprintf(stderr,"System is %s\n",data->system);
     fprintf(stderr,"prompt is %s\n",data->system);


    // Create thread for gpt4
    if (pthread_create(&thread, NULL, llmproxy_request, data) != 0) {
        fprintf(stderr, "Error creating thread for gpt4\n");
        free(data);
        exit(EXIT_FAILURE);
    }

    // Join thread
    pthread_join(thread, NULL);
    free(data); // Free allocated memory
}


char *sanitize_json(const char *input) {
    // Allocate buffer for sanitized string
    char *sanitized = malloc(strlen(input) * 2 + 1); // Worst-case: every character escaped
    char *dest = sanitized;

    // Escape special characters
    while (*input) {
        if (*input == '"' || *input == '\\') {
            *dest++ = '\\';
        }
        *dest++ = *input++;
    }
    *dest = '\0';
    return sanitized;
}
void send_json_response2(SSL *client_socket, char *gpt4_response) {
    char *safe_gpt4 = sanitize_json(gpt4_response);

    char response[4096];
    snprintf(response, sizeof(response),
             "{\"gpt4\": \"%s\"}", safe_gpt4);

    printf("Final JSON response: %s\n", response); // Log JSON response

    size_t http_max_size = strlen(response) + 512;

    // Prepare HTTP response
    char *http_response = malloc(http_max_size);
    snprintf(http_response, http_max_size,
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %ld\r\n\r\n"
             "%s",
             strlen(response), response);

    printf("HTTP response sent: %s\n", http_response); // Log HTTP response

    SSL_write(client_socket, http_response, strlen(http_response));

    free(safe_gpt4);
    free(http_response);
}


void send_json_response(SSL *client_socket, char *gpt4_response, char *claude_response, char *phi_response) {
    char *safe_gpt4 = sanitize_json(gpt4_response);
    char *safe_claude = sanitize_json(claude_response);
    char *safe_phi = sanitize_json(phi_response);
    
    char response[8192];
    snprintf(response, sizeof(response),
             "{\"gpt4\": \"%s\", \"claude\": \"%s\", \"phi\": \"%s\"}",
             safe_gpt4, safe_claude, safe_phi);

    printf("Final JSON response: %s\n", response); // Log JSON response

    size_t http_max_size = strlen(response) + 512;

    // Calculate content length
    char *http_response = malloc(http_max_size);
    snprintf(http_response, http_max_size,
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %ld\r\n\r\n"
             "%s",
             strlen(response), response);

    printf("HTTP response sent: %s\n", http_response); // Log HTTP response

    SSL_write(client_socket, http_response, strlen(http_response));

    free(safe_gpt4);
    free(safe_claude);
    free(safe_phi);
}



void parse_json_payload(const char *buffer, char *prompt, 
                        char *lastk, char *temperature, char *system) {
    // Find the start of the JSON payload
    const char *json_start = strstr(buffer, "\r\n\r\n");
    if (json_start == NULL) {
        printf("Invalid request: No JSON payload found.\n");
        return;
    }

    // Move pointer to the actual JSON (after the blank line)
    json_start += 4;

    // Use sscanf to parse the JSON payload
    if (sscanf(json_start,
               "{\"prompt\":\"%[^\"]\",\"lastk\":\"%[^\"]\",\"temperature\":\"%[^\"]\",\"system\":\"%[^\"]\"}",
               prompt, lastk, temperature, system) != 4) {
        printf("Failed to parse JSON payload.\n");
    } else {
        printf("Parsed JSON successfully:\n"
               "Prompt: %s\n"
               "LastK: %s\n"
               "Temperature: %s\n"
               "System: %s\n", 
               prompt, lastk, temperature, system);
    }
}
#define MAX_SYSTEM_LEN 2000
#define MAX_PROMPT_LEN 512

int parse_json_payload2(const char *json, char *prompt, char *system) {
    const char *start_system = strstr(json, "\"system\":");
    const char *start_prompt = strstr(json, "\"prompt\":");

    if (start_system == NULL || start_prompt == NULL) {
        fprintf(stderr, "Failed to find 'system' or 'prompt' in JSON.\n");
        return 1; // Indicate failure
    }

    // Extract "system" value
    start_system += 9; // Skip "\"system\":"
    while (*start_system == ' ' || *start_system == '\t') {
        start_system++;
    }
    if (*start_system != '"') {
        fprintf(stderr, "Invalid 'system' field format.\n");
        return 1;
    }
    start_system++; // Skip the opening quote

    const char *end_system = strchr(start_system, '"');
    if (end_system == NULL) {
        fprintf(stderr, "Invalid 'system' field format.\n");
        return 1;
    }

    size_t system_len = end_system - start_system;
    if (system_len >= MAX_SYSTEM_LEN) {
        fprintf(stderr, "System field exceeds maximum length.\n");
        return 1;
    }

    strncpy(system, start_system, system_len);
    system[system_len] = '\0';

    // Extract "prompt" value
    start_prompt += 9; // Skip "\"prompt\":"
    while (*start_prompt == ' ' || *start_prompt == '\t') {
        start_prompt++;
    }
    if (*start_prompt != '"') {
        fprintf(stderr, "Invalid 'prompt' field format.\n");
        return 1;
    }
    start_prompt++; // Skip the opening quote

    const char *end_prompt = strchr(start_prompt, '"');
    if (end_prompt == NULL) {
        fprintf(stderr, "Invalid 'prompt' field format.\n");
        return 1;
    }

    size_t prompt_len = end_prompt - start_prompt;
    if (prompt_len >= MAX_PROMPT_LEN) {
        fprintf(stderr, "Prompt field exceeds maximum length.\n");
        return 1;
    }

    strncpy(prompt, start_prompt, prompt_len);
    prompt[prompt_len] = '\0';

    // Success
    fprintf(stderr, "Sytem is %s\n", system);
    fprintf(stderr, "Prompt is %s\n", prompt);
    return 0; // Indicate success
}

void cleanup(SOCKET client_socket, SOCKET server_socket, SSL *ssl_client, SSL *server_ssl) {
    close(client_socket);
    close(server_socket);
    SSL_shutdown(ssl_client);
    SSL_shutdown(server_ssl);
    SSL_free(ssl_client);
    SSL_free(server_ssl);
}

/*--------------------------------------------------------------------------------------*/

// This function is called by libcurl to write data into a string buffer
size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    char *data = (char *)userdata;
    size_t total_size = size * nmemb;

    if (data != NULL) {
        size_t current_length = strlen(data);
        if (current_length + total_size < 4096 - 1) { // Ensure buffer doesn't overflow
            strncat(data, ptr, total_size);
        } else {
            fprintf(stderr, "Response buffer overflow detected!\n");
        }
    }
    return total_size;
}



void *llmproxy_request(void *arg) {
    ThreadData data = (ThreadData)arg;
    CURL *curl;
    CURLcode res;

    char request[4096];
    snprintf(request, sizeof(request),
             "{\n"
             "  \"model\": \"%s\",\n"
             "  \"system\": \"%s\",\n"
             "  \"query\": \"%s\",\n"
             "  \"temperature\": %.2f,\n"
             "  \"lastk\": %d,\n"
             "  \"session_id\": \"GenericSession\"\n"
             "}",
             data->model, data->system, data->prompt, data->temp, data->lastK);

    printf("Initiating request: %s\n", request);

    // Initialize CURL
    curl = curl_easy_init();
    if (curl) {
        // Set the URL
        curl_easy_setopt(curl, CURLOPT_URL, "https://a061igc186.execute-api.us-east-1.amazonaws.com/dev");

        // Set headers
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "x-api-key: comp11286nkWwDMdwZAmd53zUetwlbhvWiKxTclwqhC1Ppl");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Set POST body
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);

        // Set response handler
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, data->response);

        // Perform request
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        // Cleanup
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    } else {
        fprintf(stderr, "Failed to initialize CURL.\n");
    }

    pthread_exit(NULL);
}
/*-------------------------------------------------------------------------------------------------------------------------------------------------------------------*/

void* thread_function3(void* arg) {
    Connection conn = (Connection)arg; 

    // Extract socket descriptors
         SOCKET client_socket = conn->client;
        EVP_PKEY *root_key = conn->root_key;
        X509 *root_cert = conn->root_cert;
        char* buffer = conn->request_buffer;
           char *host_header = strstr(buffer, "Host: ");
                    if (!host_header) {
                        fprintf(stderr, "Missing Host header in request.\n");
                        close(client_socket);
                        return NULL;
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
                        return NULL;
                    }

                SSL_set_fd(ssl_client, client_socket);  
                fprintf(stderr,"Trying to establish SSL with client\n");
                if (SSL_accept(ssl_client) <= 0) {
                    // Handle handshake error, use SSL_get_error() to get more details
                     SSL_free(ssl_client);
                     fprintf(stderr,"Failed SSL with client , disconnecting both endpoints\n");
                     close(client_socket);
                    // close(server_socket);
                          return NULL;
                
                }
                fprintf(stderr,"SSL with client established\n");

                    // Parse the Host header
                  

                    printf("Connecting to server %s on port %s...\n", host_header, "443");

                    // Connect to the target server
                    SOCKET server_socket = connect_to_host(host_header, "443");
                    if (!ISVALIDSOCKET(server_socket)) {
                        fprintf(stderr, "Failed to connect to server %s:%s\n", host_header, "443");
                        close(client_socket);
                       
                        return NULL;
                    }
                    // set_nonblocking(server_socket);
                    
                    SSL* server_ssl = ssl_with_server(server_socket);
                    if(server_ssl == NULL) {
                        fprintf(stderr,"SSL Handshake with server failed\n");
                        close(client_socket);
                        close(server_socket);
                     return NULL;
                    }
   

    fd_set readfds;
    

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(client_socket, &readfds);
        FD_SET(server_socket, &readfds);

        SOCKET max_sd = (client_socket > server_socket) ? client_socket : server_socket;

        int activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        if (activity < 0) {
            perror("select failed");
            break;
        }
       

        // Check client socket
        if (FD_ISSET(client_socket, &readfds)) {

            char buffer[BUFFER_SIZE];    
            int bytes_read = SSL_read(ssl_client, buffer, sizeof(buffer));
            printf("client buffer :\n %s\n",buffer);
            if (bytes_read <= 0) {
                
                  close(client_socket);
                 close(server_socket);
                 SSL_shutdown(ssl_client);
                 SSL_shutdown(server_ssl);
                 SSL_free(ssl_client);
                 SSL_free(server_ssl);
                 free(conn);
                 return NULL;
            }
           
               if (strstr(buffer, "GET /chatbot.js ")) {
                send_file_response(ssl_client, "chatbot.js");
                continue;
                // User clicked Generate button
            } 
            else if (strstr(buffer, "POST /query") != NULL) {
        // Parse incoming JSON payload
        printf("REQUEST BUFFER:\n%s\n", buffer);

        char prompt[512] = {0}, system[2000] = {0};
        parse_json_payload2(buffer, prompt, system);

        
    // Set lastk to 0 and temperature to a low value (e.g., 0.1)
    int lastk = 0;
    double temperature = 0.1;

    // Get the response from gpt4
    char gpt4_response[4096] = {0};
    execute_threads2(prompt, temperature, lastk, system, gpt4_response);

    printf("Response from GPT-4: %s\n", gpt4_response);

    // Send the JSON response back to the client
    send_json_response2(ssl_client, gpt4_response);
        continue;
    }
            
            int bytes_sent = SSL_write(server_ssl,buffer,bytes_read);
            if(bytes_sent<=0){
                //TODO
                    close(client_socket);
                 close(server_socket);
                 SSL_shutdown(ssl_client);
                 SSL_shutdown(server_ssl);
                 SSL_free(ssl_client);
                 SSL_free(server_ssl);
                 free(conn);
                 return NULL;
            }
           
        }



if (FD_ISSET(server_socket, &readfds)) {
    FILE *fp = fopen("output.txt", "ab");
    if (!fp) {
        perror("fopen");
        return NULL;
    }

    char header_buffer[BUFFER_SIZE];
    char body_buffer[BUFFER_SIZE];
    int header_bytes_read = 0;

    // Read the headers (and possibly part of the body)
    header_bytes_read = SSL_read(server_ssl, header_buffer, sizeof(header_buffer) - 1);
    if (header_bytes_read <= 0) {
        // Connection closed or error
        close(client_socket);
        close(server_socket);
        SSL_shutdown(ssl_client);
        SSL_shutdown(server_ssl);
        SSL_free(ssl_client);
        SSL_free(server_ssl);
        free(conn);
        return NULL;
    }

    // Null-terminate the header for parsing
    header_buffer[header_bytes_read] = '\0';

    // Locate the end of the headers
    char *header_end = strstr(header_buffer, "\r\n\r\n");
    if (!header_end) {
        // No headers found, just forward as is
        fwrite(header_buffer, 1, (size_t)header_bytes_read, fp);
        fclose(fp);
        SSL_write(ssl_client, header_buffer, header_bytes_read);
        return NULL;
    }

    // Check if Content-Type is text/html
    char *content_type = strcasestr(header_buffer, "Content-Type:");
    int is_html = 0;
    if (content_type && content_type < header_end) {
        content_type += strlen("Content-Type:");
        while (*content_type == ' ' || *content_type == '\t') content_type++;
        if (strncasecmp(content_type, "text/html", 9) == 0) {
            is_html = 1;
        }
    }

    // Calculate how much of the body (if any) was read along with the headers
    size_t header_len = (size_t)(header_end - header_buffer) + 4; // Include "\r\n\r\n"
    size_t body_offset = header_bytes_read - header_len;

    if (is_html) {
        size_t body_bytes_read = 0;
        if (body_offset > 0) {
            // Part of the body was already read
            memcpy(body_buffer, header_buffer + header_len, body_offset);
            body_bytes_read = body_offset;
        }

        // Read the remaining body if necessary
        if (body_bytes_read < BUFFER_SIZE - 1) {
            int additional_bytes_read = SSL_read(server_ssl, body_buffer + body_bytes_read,
                                                 sizeof(body_buffer) - body_bytes_read - 1);
            if (additional_bytes_read > 0) {
                body_bytes_read += additional_bytes_read;
            }
        }

        // Null-terminate the body for parsing
        body_buffer[body_bytes_read] = '\0';

        // Locate the </body> tag
        char *body_close = NULL;
        for (char *p = body_buffer; *p; p++) {
            if (strncasecmp(p, "</body>", 7) == 0) {
                body_close = p;
                break;
            }
        }

        const char *SCRIPT_BLOCK = "<div id=\"chatbot\"><script src=\"/chatbot.js\"></script></div>";
        size_t script_len = strlen(SCRIPT_BLOCK);

        char modified_body[BUFFER_SIZE];
        size_t new_body_len = 0;

        if (body_close) {
            printf("Detected </body> tag at position: %ld\n", body_close - body_buffer);

            // Copy everything up to </body>
            size_t before_body_len = (size_t)(body_close - body_buffer);
            memcpy(modified_body, body_buffer, before_body_len);
            new_body_len += before_body_len;

            // Insert the chatbot div before </body>
            memcpy(modified_body + new_body_len, SCRIPT_BLOCK, script_len);
            new_body_len += script_len;

            // Copy the rest of the body including </body>
            size_t after_body_len = strlen(body_close);
            memcpy(modified_body + new_body_len, body_close, after_body_len + 1); // +1 for null terminator
            new_body_len += after_body_len;
        } else {
            printf("No </body> tag detected. Appending chatbot at the end.\n");

            // If </body> is not found, append chatbot div at the end
            memcpy(modified_body, body_buffer, body_bytes_read);
            new_body_len += body_bytes_read;
            memcpy(modified_body + new_body_len, SCRIPT_BLOCK, script_len);
            new_body_len += script_len;
        }

        // Update Content-Length in the headers
        char *cl_header = strcasestr(header_buffer, "Content-Length:");
        if (cl_header && cl_header < strstr(header_buffer, "\r\n\r\n")) {
            cl_header += strlen("Content-Length:");
            while (*cl_header == ' ' || *cl_header == '\t') cl_header++;
            char *line_end = strstr(cl_header, "\r\n");
            if (line_end) {
                char new_length_str[64];
                snprintf(new_length_str, sizeof(new_length_str), "%zu", new_body_len);

                // Update Content-Length in the headers
                size_t length_to_move = strlen(line_end);
                memmove(cl_header, new_length_str, strlen(new_length_str));
                memmove(cl_header + strlen(new_length_str), line_end, length_to_move + 1);
            }
        }

        // Write the modified response to the file for debugging
        fwrite(header_buffer, 1, header_bytes_read, fp);
        fwrite(modified_body, 1, new_body_len, fp);
        fclose(fp);

        // Send the updated header to the client
        SSL_write(ssl_client, header_buffer, header_bytes_read);

        // Send the modified body to the client
        SSL_write(ssl_client, modified_body, (int)new_body_len);
    } else {
        // Not HTML, just forward as is
        fwrite(header_buffer, 1, (size_t)header_bytes_read, fp);
        fclose(fp);
        SSL_write(ssl_client, header_buffer, header_bytes_read);
    }
}
    }
return NULL;
}

/*--------------------------------------------------------------------------------------*/

int main(int argc , char* argv[]){
        assert(argc==2);
          signal(SIGPIPE, SIG_IGN);
        char* port_no = argv[1];
        SOCKET proxy_server = create_server_socket(port_no);
          EVP_PKEY *root_key = load_root_key("private_key.pem");
        assert(root_key!= NULL);
        X509 *root_cert = load_root_cert("rootCA.crt");
        assert(root_cert!= NULL);
        // unsigned long curr_threads = 0;
        while (1) 
        {
        fd_set readfds; 
        FD_ZERO(&readfds);
        FD_SET(proxy_server, &readfds);
        int max_sd = proxy_server;
        fprintf(stderr,"Waiting for message or connection request\n");    
        
        int activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        if (activity < 0) {
            fprintf(stderr, "select() error\n");
            break;
        }

        if(FD_ISSET(proxy_server, &readfds)) 
        {   fprintf(stderr,"Connection request at listening socket\n");
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
                    char buffer[1000];
                    int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
                    if (bytes_received <= 0) {
                        fprintf(stderr, "Failed to receive data from client.\n");
                        close(client_socket);
                        
                        continue;
                    }
                    buffer[bytes_received] = '\0'; // Null-terminate the request

                    printf("Received client request:\n%s\n", buffer);
                      char *host_header = strstr(buffer, "Host: ");
                    if (!host_header) {
                        fprintf(stderr, "Missing Host header in request.\n");
                        close(client_socket);
                        return 1;
                    }

                    host_header += 6; // Skip "Host: "
                    char *end_of_host = strstr(host_header, "\r\n");
                    if (end_of_host) *end_of_host = '\0';
                    printf("Hostname is %s\n",host_header);
                    



                    send_200(client_socket);
                   
                    
                    

                    //CREATE AND RUN NEW THREAD HANDLING CONNECTION  
                    Connection new_connection = malloc(sizeof(struct Connection));
                    new_connection->client = client_socket;
                    memcpy(new_connection->request_buffer,buffer,1000);
                    new_connection->root_cert = root_cert;
                    new_connection->root_key = root_key;
                    pthread_t thread_id; // = curr_threads++;
                    if(strcmp(host_header,"chatgpt.com:443")==0){
                    if (pthread_create(&thread_id, NULL, thread_function2, (void*)new_connection) != 0) {
                         perror("pthread_create failed");
                         free(new_connection); // Free memory if thread creation fails
                         close(client_socket);
                         continue;
                         }
                    }
                     
                      else if(strcmp(host_header,"www.cs.tufts.edu:443")==0){
                          if (pthread_create(&thread_id, NULL, thread_function3, (void*)new_connection) != 0) {
                         perror("pthread_create failed");
                         free(new_connection); // Free memory if thread creation fails
                         close(client_socket);
                         continue;
                         }

                    }
                     else {
                          if (pthread_create(&thread_id, NULL, thread_function, (void*)new_connection) != 0) {
                         perror("pthread_create failed");
                         free(new_connection); // Free memory if thread creation fails
                         close(client_socket);
                         continue;
                         }

                    }
                    
        }
    }

}
