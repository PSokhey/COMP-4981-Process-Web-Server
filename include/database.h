//
// Created by prabh on 01/04/23.
//

#ifndef PROCESS_SERVER_DATABASE_H
#define PROCESS_SERVER_DATABASE_H

#include <bits/stdint-uintn.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <ndbm.h>
#include <string.h>

// gererate a random UUID
void generate_uuid(char *uuid_str);

// print all data in the database for debugging purposes
void print_db();

// delete the database.
void delete_db();

// get all the content in  the dataset
char *get_database_content();

#endif //PROCESS_SERVER_DATABASE_H

