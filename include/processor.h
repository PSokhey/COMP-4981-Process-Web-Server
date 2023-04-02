#ifndef MULTIPLEX_PROCESSOR_H
#define MULTIPLEX_PROCESSOR_H


#include <dc_env/env.h>
#include <dc_error/error.h>
#include <stdint.h>
#include <sys/types.h>
#include "database.h"


ssize_t read_message_handler(const struct dc_env *env, struct dc_error *err, uint8_t **raw_data, int client_socket);
size_t process_message_handler(const struct dc_env *env, struct dc_error *err, const uint8_t *raw_data, uint8_t **processed_data, ssize_t count, int client_socket);
void send_message_handler(const struct dc_env *env, struct dc_error *err, uint8_t *buffer, size_t count, int client_socket, bool *closed);

// added functions

// For sending response to the client
void send_http_response(const struct dc_env *env, struct dc_error *err, int client_socket, int status_code, const char *content_type, const char *content);


#endif //MULTIPLEX_PROCESSOR_H
