//
// Created by prabh on 01/04/23.
//
#include "database.h"

void generate_uuid(char *uuid_str) {
    // Seed the random number generator
    srand(time(NULL));

    // Generate the UUID parts
    uint32_t part1 = rand();
    uint16_t part2 = rand();
    uint16_t part3 = (rand() & 0x0FFF) | 0x4000; // Set the version to 4
    uint16_t part4 = (rand() & 0x3FFF) | 0x8000; // Set the variant to 1 (RFC4122)
    uint32_t part5 = rand();
    uint32_t part6 = rand();

    // Format the UUID string
    sprintf(uuid_str,
            "%08x-%04x-%04x-%04x-%08x%08x",
            part1, part2, part3, part4, part5, part6);
}

// print all data in the database for debugging purposes
void print_db() {

    DBM* db = dbm_open("database", O_CREAT | O_RDWR, 0666);

    datum k, v;

    printf("\nFollowing messages are stored in the database:\n");

    // iterate over all entries in the database
    for (k = dbm_firstkey(db); k.dptr; k = dbm_nextkey(db)) {
        // retrieve the value (the message) from the database
        v = dbm_fetch(db, k);
        if (v.dptr) {
            // print the key and value
            //printf(" %.*s\n", (int)v.dsize, v.dptr);
            printf("%.*s: %.*s\n", (int)k.dsize, k.dptr, (int)v.dsize, v.dptr);
            dbm_clearerr(db);
        } else {
            fprintf(stderr, "Key not found.\n");
        }
    }

    dbm_close(db);
}

// delete all entries in the database.
void delete_db() {

    DBM* db;
    db = dbm_open("database", O_RDWR, 0666);
    if (!db) {
        fprintf(stderr, "Error: Failed to open database.\n");
        exit(1);
    }

    datum key;
    key = dbm_firstkey(db);
    while (key.dptr != NULL) {
        if (dbm_delete(db, key) == -1) {
            fprintf(stderr, "Error: Failed to delete key %s from database.\n", key.dptr);
            exit(1);
        }

        // get the next key, using first instead next because pier first key is now deleted.
        key = dbm_firstkey(db);
    }

    printf("Database deleted successfully.\n");

    dbm_close(db);

}

// get all content in the current databse.
char *get_database_content() {
    // Open the database
    DBM *db = dbm_open("database", O_RDONLY, 0666);
    if (!db) {
        fprintf(stderr, "Database Error: Database could not be opened.\n");
        return NULL;
    }

    // Initialize an empty string to store the content
    char *content = calloc(1, sizeof(char));
    if (!content) {
        fprintf(stderr, "Memory Error: Could not allocate memory for content.\n");
        return NULL;
    }

    // Iterate through the key-value pairs in the database
    datum key, value;
    for (key = dbm_firstkey(db); key.dptr != NULL; key = dbm_nextkey(db)) {
        value = dbm_fetch(db, key);

        if (value.dptr != NULL) {
            // Calculate the new content size (key size, value size, separators, and null terminator)
            size_t new_content_size = strlen(content) + key.dsize + value.dsize + 4;

            // Reallocate memory for the new content size
            char *new_content = realloc(content, new_content_size);
            if (new_content == NULL) {
                fprintf(stderr, "Memory Error: Could not allocate memory for database content.\n");
                dbm_close(db);
                free(content);
                return NULL;
            }

            // Append the key-value pair to the content string
            content = new_content;
            strncat(content, key.dptr, key.dsize);
            strncat(content, " = ", 3);
            strncat(content, value.dptr, value.dsize);
            strncat(content, ";", 1); // Add a separator between key-value pairs
            strncat(content, "\n", 1); // Add new space at the end.
        }
    }

    // Close the database
    dbm_close(db);

    // Return the content string
    return content;
}


