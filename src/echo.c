#include "processor.h"
#include <dc_c/dc_stdlib.h>
#include <dc_c/dc_string.h>
#include <dc_posix/dc_unistd.h>
#include <dc_util/io.h>
#include <stdio.h>
#include <string.h>
#include <dc_posix/dc_string.h>

static const int BLOCK_SIZE = 1024 * 4;

struct http_request {
    char* method;
    char* resource;
    char* version;
    char* agent;
    char* host;
    char* language;
    char* encoding;
    char* keep_connection;
};

static void parse_request(const struct dc_env *env, const struct dc_error *err, struct http_request *http, char* req) {
    DC_TRACE(env);
    printf("Request received:\n%s\n", req);
    
    char* tempreq;
    tempreq = strdup(req);

    http->method = dc_strtok_r(env, tempreq, " ", &tempreq);
    http->resource = dc_strtok_r(env, tempreq, " ", &tempreq);
    http->version = dc_strtok_r(env, tempreq, "\n", &tempreq);
    char* token;
    while ((token = dc_strtok_r(env, tempreq, "\n", &tempreq)) != NULL) {
        char* field;
        field = dc_strtok_r(env, token, " ", &token);
        if (dc_strcmp(env, field, "User-Agent:") == 0) {
            http->agent = token;
        } else if (dc_strcmp(env, field, "Host:") == 0) {
            http->host = token;
        } else if (dc_strcmp(env, field, "Accept-Language:") == 0) {
            http->language = token;
        } else if (dc_strcmp(env, field, "Accept-Encoding:") == 0) {
            http->encoding = token;
        } else if (dc_strcmp(env, field, "Connection:") == 0) {
            http->keep_connection = token;
        }
    }
}

// reads data sent from the client.
// TODO: READ THE MESSAGE FROM THE CLIENT.
ssize_t read_message_handler(const struct dc_env *env, struct dc_error *err, uint8_t **raw_data, int client_socket)
{
    ssize_t bytes_read;
    size_t buffer_len;
    uint8_t *buffer;

    DC_TRACE(env);
    buffer_len = BLOCK_SIZE * sizeof(*buffer);
    buffer = dc_malloc(env, err, buffer_len);
    bytes_read = dc_read(env, err, client_socket, buffer, buffer_len);

    if(dc_error_has_no_error(err))
    {
        *raw_data = dc_malloc(env, err, bytes_read);
        dc_memcpy(env, *raw_data, buffer, bytes_read);
    }
    else
    {
        *raw_data = NULL;
    }

    dc_free(env, buffer);

    return bytes_read;
}

// processes the data sent from the client.


// TODO: PROCESS HTTP REQUEST HERE.
size_t process_message_handler(const struct dc_env *env, struct dc_error *err, const uint8_t *raw_data, uint8_t **processed_data, ssize_t count)
{
    struct http_request http;
    size_t processed_length;

    DC_TRACE(env);

    parse_request(env, err, &http, raw_data);

    printf("method:% s\n", http.method);
    printf("resource: %s\n", http.resource);
    printf("version: %s\n", http.version);

    printf("\nRout tracking:\n\n");
    // If the http request is a GET request then do the following
    if (strcmp(http.method, "GET") == 0) {
        printf("GET request received\n");

        // If the resource is / then send the index.html file
        if (http.resource == "/") {

        }
    }

    else if (strcmp(http.method, "HEAD") == 0) {
        printf("HEAD request received\n");

    }

    else if (strcmp(http.method, "POST") == 0) {
        printf("POST request received\n");

    }

    else {
        // If the http request is not a valid request then send a 400 Bad Request response
    }

    processed_length = count * sizeof(**processed_data);
    *processed_data = dc_malloc(env, err, processed_length);
    dc_memcpy(env, *processed_data, raw_data, processed_length);

    return processed_length;
}

// sends data back to the client.
// TODO: SEND HTTP RESPONSE HERE.
void send_message_handler(const struct dc_env *env, struct dc_error *err, uint8_t *buffer, size_t count, int client_socket, bool *closed)
{
    DC_TRACE(env);
    dc_write_fully(env, err, client_socket, buffer, count);
    *closed = false;
}
