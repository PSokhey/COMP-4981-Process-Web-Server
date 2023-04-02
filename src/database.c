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