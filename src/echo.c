#include "processor.h"
#include <dc_c/dc_stdlib.h>
#include <dc_c/dc_string.h>
#include <dc_posix/dc_unistd.h>
#include <dc_util/io.h>
#include <string.h>
#include <dc_posix/dc_string.h>

#define REQUEST_SUCCESS 200
#define REQUEST_NOT_FOUND 404
#define BAD_REQUEST 400
#define SERVER_ERROR 500
#define REQUEST_SUCCESS_NO_CONTENT 204
#define REQUEST_CREATED_IN_DATABASE 201
#define INTERNAL_SERVER_ERROR 500
#define BAD_REQUEST 400

#define MAX_MESSAGE_SIZE 4096




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

int parse_json(const char *json_data, char *key_str, char *message) {
    const char *key_start = strstr(json_data, "\"key\":\"");
    const char *key_end = NULL;

    if (key_start != NULL) {
        key_start += strlen("\"key\":\"");
        key_end = strchr(key_start, '\"');
        if (key_end != NULL) {
            int key_length = key_end - key_start;
            strncpy(key_str, key_start, key_length);
            key_str[key_length] = '\0';
        }
    }

    const char *msg_start = strstr(json_data, "\"message\":\"");
    if (msg_start == NULL) {
        return -1;
    }

    msg_start += strlen("\"message\":\"");
    const char *msg_end = strchr(msg_start, '\"');
    if (msg_end == NULL) {
        return -1;
    }

    int message_length = msg_end - msg_start;

    if(message_length > MAX_MESSAGE_SIZE || message_length <= 0) {
        return -1;
    }

    strncpy(message, msg_start, message_length);
    message[message_length] = '\0';

    return 0;
}


// sending a response to the client.
void send_http_response(const struct dc_env *env, struct dc_error *err, int client_socket, int status_code, const char *content_type, const char *content) {
    char response_header[256];
    size_t content_length = strlen(content);

    snprintf(response_header, sizeof(response_header),
             "HTTP/1.0 %d OK\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %zu\r\n"
             "\r\n",
             status_code, content_type, content_length);

    dc_write_fully(env, err, client_socket, (uint8_t *)response_header, strlen(response_header));
    dc_write_fully(env, err, client_socket, (uint8_t *)content, content_length);
}
void send_http_error(const struct dc_env *env, struct dc_error *err, int client_socket, int error_code, const char* error_msg, const char* error_body) {
    char response_header[256];
    size_t body_length = strlen(error_body);

    printf("%s\n", error_body);

    snprintf(response_header, sizeof(response_header),
             "HTTP/1.0 %d %s\r\n"
             "Content-Type: text/html\r\n"
             "Content-Length: %zu\r\n"
             "\r\n", error_code, error_msg, body_length);

    dc_write_fully(env, err, client_socket, (uint8_t *)response_header, strlen(response_header));
    dc_write_fully(env, err, client_socket, (uint8_t *)error_body, body_length);
}
// sending a response to the client.
void send_http_head_response(const struct dc_env *env, struct dc_error *err, int client_socket, int status_code, const char *content_type, off_t content_length) {
    char response_header[256];

    snprintf(response_header, sizeof(response_header),
             "HTTP/1.0 %d OK\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %zu\r\n"
             "\r\n",
             status_code, content_type, content_length);

    dc_write_fully(env, err, client_socket, (uint8_t *)response_header, strlen(response_header));
}

static bool ends_with(const char* string, const char* suffix) {
    size_t ext_len = strlen(suffix);
    size_t file_len = strlen(string) - ext_len;

    if (file_len < 0) {
        return false;
    } else {
        return !memcmp(string + file_len, suffix, ext_len);
    }
}

char* get_content_type(char* resource) {
    if (ends_with(resource, ".html")) {
        return strdup("text/html");
    } else if (ends_with(resource, ".css")) {
        return strdup("text/css");
    } else if (ends_with(resource, ".js")) {
        return strdup("text/javascript");
    } else if (ends_with(resource, ".png")) {
        return strdup("image/png");
    } else if (ends_with(resource, ".jpg") || ends_with(resource, ".jpeg")) {
        return strdup("image/jpeg");
    } else if (ends_with(resource, ".gif")) {
        return strdup("image/gif");
    } else if (ends_with(resource, ".bmp")) {
        return strdup("image/bmp");
    } else if (ends_with(resource, ".mp3")) {
        return strdup("audio/mp3");
    } else if (ends_with(resource, ".wav")) {
        return strdup("audio/wav");
    } else if (ends_with(resource, ".mp4")) {
        return strdup("video/png");
    } else if (ends_with(resource, ".avi")) {
        return strdup("video/png");
    } else if (ends_with(resource, ".pdf")) {
        return strdup("application/pdf");
    } else if (ends_with(resource, ".xml")) {
        return strdup("application/xml");
    } else if (ends_with(resource, ".json")) {
        return strdup("application/json");
    } else if (ends_with(resource, ".txt")) {
        return strdup("text/plain");
    } else if (ends_with(resource, ".ttf")) {
        return strdup("font/ttf");
    } else if (ends_with(resource, ".otf")) {
        return strdup("font/otf");
    } else if (ends_with(resource, ".zip")) {
        return strdup("application/zip");
    } else if (ends_with(resource, ".tar")) {
        return strdup("application/tar");
    } else {
        return strdup("application/octet-string");
    }
}

// reads data sent from the client.
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
size_t process_message_handler(const struct dc_env *env, struct dc_error *err, const uint8_t *raw_data, uint8_t **processed_data, ssize_t count, int client_socket)
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
        char* content;
        char* content_type;
        int fd = 0;

        // If the resource is / then send the index.html file
        if (strcmp(http.resource, "/") == 0) {
            //printf("index.html request received\n");
            // send the index.html file
            //printf("File requested: ./web/index.html\n");
            fd = open("./web/index.html", O_RDONLY | O_SYNC);
            //printf("fd: %d\n", fd);
            if (fd <= 0) {
                //char* error = file_not_found(http.resource);
                send_http_error(env, err, client_socket, REQUEST_NOT_FOUND, "Not Found", file_not_found(http.resource));
            } else {
                off_t file_size = lseek(fd, 0, SEEK_END);
                if (lseek(fd, 0, SEEK_SET) < 0) {
                    send_http_error(env, err, client_socket, SERVER_ERROR, "Internal Server Error", internal_server_body());
                } else {
                    content = malloc(file_size);
                    read(fd, content, file_size);
                    content_type = strdup("text/html");
                    send_http_response(env, err, client_socket, REQUEST_SUCCESS, content_type, content);
                    free(content);
                    close(fd);
                }
            }
        }

        // if request for what is in the database.
        else if (strcmp(http.resource, "/getDatabase") == 0) {
            // send the database file
            printf("database log request received\n");
            // test what is currently in the database.
            printf("\nFollowing is what is currently in the database:\n\n");
            print_db();

            // Send a response indicating the data was successfully stored
            const char *content_type = "text/plain";
            //const char *content = "Database replied successfully.";

            // get the content in the databse.
            char *content = get_database_content();

            if (content != NULL) {
                printf("\ncontent sent as a response: %s\n", content);
                send_http_response(env, err, client_socket, REQUEST_SUCCESS, content_type, content);
            } else
                send_http_response(env, err, client_socket, REQUEST_SUCCESS, content_type, "Database is empty.");



        } else {
            char* reqconcat;
            reqconcat = strdup("./web");
            reqconcat = strcat(reqconcat, http.resource);
            fd = open(reqconcat, O_RDONLY | O_SYNC);
            if (fd <= 0) {
                printf("File not found\n");
                char* error = file_not_found(http.resource);
                printf("%s\n", error);
                send_http_error(env, err, client_socket, REQUEST_NOT_FOUND, "Not Found", error);
            } else {
                off_t file_size = lseek(fd, 0, SEEK_END);
                if (lseek(fd, 0, SEEK_SET) < 0) {
                    send_http_error(env, err, client_socket, SERVER_ERROR, "Internal Server Error", internal_server_body());
                } else {
                    printf("Requested file found found: %s\n", reqconcat);
                    content = malloc(file_size);
                    read(fd, content, file_size);
                    content_type = get_content_type(http.resource);
                    send_http_response(env, err, client_socket, REQUEST_SUCCESS, content_type, content);
                    free(content);
                    close(fd);
                }
            }
        }
    }

    else if (strcmp(http.method, "HEAD") == 0) {
        //printf("HEAD request received\n");
        char *content;
        content = malloc(BLOCK_SIZE * BLOCK_SIZE);
        char *content_type;
        int fd;

        // If the resource is / then send the index.html file
        if (strcmp(http.resource, "/") == 0) {
            //printf("index.html request received\n");
            // send the index.html file
            //printf("File requested: ./web/index.html\n");
            fd = open("./web/index.html", O_RDONLY | O_SYNC);
            //printf("fd: %d\n", fd);
            if (fd <= 0) {

            } else {
                off_t file_size = lseek(fd, 0, SEEK_END);
                if (lseek(fd, 0, SEEK_SET) < 0) {

                } else {
                    content_type = strdup("text/html");
                    send_http_head_response(env, err, client_socket, REQUEST_SUCCESS, content_type, file_size);
                    free(content);
                    close(fd);
                }
            }
        } else {
            char* reqconcat;
            reqconcat = strdup("./web");
            reqconcat = strcat(reqconcat, http.resource);
            fd = open(reqconcat, O_RDONLY | O_SYNC);
            if (fd <= 0) {

            } else {
                off_t file_size = lseek(fd, 0, SEEK_END);
                if (lseek(fd, 0, SEEK_SET) < 0) {

                } else {
                    printf("Requested file found found: %s\n", reqconcat);
/*                    content = malloc(file_size);
                    read(fd, content, file_size);*/
                    content_type = get_content_type(http.resource);
                    send_http_head_response(env, err, client_socket, REQUEST_SUCCESS, content_type, file_size);
                    free(content);
                    close(fd);
                }
            }
        }
    }

    else if (strcmp(http.method, "POST") == 0) {
        printf("POST request received and inserting to database.\n");

        char* json_data = strstr(raw_data, "\r\n\r\n") + 4;

        char key_str[37] = {0};
        char message[MAX_MESSAGE_SIZE] = {0};

        if (parse_json(json_data, key_str, message) != 0) {
            send_http_response(env, err, client_socket, BAD_REQUEST, "text/plain", "JSON Error: Failed to parse JSON data.");
            free(json_data);
            return 0;
        }

        if (strlen(key_str) == 0) {
            generate_uuid(key_str);
        }

        DBM *db = dbm_open("database", O_CREAT | O_RDWR, 0666);

        if (!db) {
            fprintf(stderr, "Database Error: Database could not be open.\n");
            send_http_response(env, err, client_socket, INTERNAL_SERVER_ERROR, "text/plain", "Unable to insert into database.");
            return 0;
        }

        datum key, value;
        key.dptr = key_str;
        key.dsize = strlen(key_str);
        value.dptr = message;
        value.dsize = strlen(message);

        if (dbm_store(db, key, value, DBM_INSERT) != 0) {
            fprintf(stderr, "Database Error: Could not insert into database.\n");
            send_http_response(env, err, client_socket, INTERNAL_SERVER_ERROR, "text/plain", "Database Error: Could not insert into the database.");
            //free(json_data);
            dbm_close(db);
            return 0;
        }

        printf("Following was inserted into the database:\n");
        printf("key: %s\n", key.dptr);
        printf("value: %s\n", value.dptr);

        printf("Sending response for success insertion\n");
        const char *content_type = "text/plain";
        const char *content = "Data stored successfully";
        send_http_response(env, err, client_socket, REQUEST_SUCCESS, content_type, content);
        printf("Response sent.\n");

        dbm_close(db);
        printf("Database closed.\n");
        //free(json_data);
        printf("json_data freed.\n");
    }

    // Delete route.
    else if(strcmp(http.method, "DELETE") == 0) {
        printf("DELETE request received\n");
        delete_db();

        // Send success response to client of deleted successfully.
        const char *content_type = "text/plain";
        const char *content = "Database deleted successfully";
        send_http_response(env, err, client_socket, REQUEST_SUCCESS, content_type, content);

    }


    else {
        // If the http request is not a valid request then send a 400 Bad Request response
        send_http_error(env, err, client_socket, BAD_REQUEST, "Bad Request", bad_request_body());
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
    //dc_write_fully(env, err, client_socket, buffer, count);
    *closed = false;


}
