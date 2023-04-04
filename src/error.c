//
// Created by cdgames on 04/04/23.
//

#include <stdio.h>
#include "error.h"

const char* file_not_found(char* resource) {
    static char err_body[1024];
    snprintf(err_body, sizeof(err_body), "<html>"
             "<head>"
             "<title>404 Not Found</title>"
             "</head>"
             "<body>"
             "<h1>404 Not Found</h1>"
             "<p>The requested URL %s was not found on this server</p>"
             "</body>"
             "</html>", resource);
    return err_body;
}

const char* internal_server_body(void) {
    return "<html>"
           "<head>"
           "<title>500 Internal Server Error</title>"
           "</head>"
           "<body>"
           "<h1>500 Internal Server Error</h1>"
           "<p>There was an unexpected error on our end</p>"
           "</body>"
           "</head>";
}

const char* bad_request_body(void) {
    return "<html>"
           "<head>"
           "<title>400 Bad Request</title>"
           "</head>"
           "<body>"
           "<h1>Bad Request</h1>"
           "<p>Your browser sent a request that this server could not understand.</p>"
           "</body>"
           "</html>";
}
