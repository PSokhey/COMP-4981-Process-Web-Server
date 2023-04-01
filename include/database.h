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
#include "database.h"

#endif //PROCESS_SERVER_DATABASE_H

// gererate a random UUID
void generate_uuid(char *uuid_str);

// print all data in the database for debugging purposes
static void print_db();