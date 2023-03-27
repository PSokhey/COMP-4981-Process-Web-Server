#include "processor.h"
#include <dc_c/dc_stdlib.h>
#include <dc_c/dc_string.h>
#include <dc_posix/dc_unistd.h>
#include <dc_util/io.h>

static const int BLOCK_SIZE = 1024 * 4;

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
    size_t processed_length;

    DC_TRACE(env);

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
