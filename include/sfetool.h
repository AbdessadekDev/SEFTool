#include "auth.h"
#ifndef SFETOOL_H
#define SFETOOL_H

#define USERS_FILE "data/users.dat"
#define USER_INFO_MAX 300

typedef enum {
    LOAD_USERS_SUCCESS = 0,
    LOAD_USERS_FILE_OPEN_ERROR = -1,
    LOAD_USERS_MEMORY_ALLOCATION_ERROR = -2,
    LOAD_USERS_DATA_FORMAT_ERROR = -3,
} LoadUsersError;


/**
 * loadUsers - Loads user data from a file and populates an array of User structs.
 * 
 * This function reads user data from a file specified by the USERS_FILE macro, where
 * each line contains a user's information in the following format:
 * 
 *     UUID|name|email|password|createdAt|updatedAt
 * 
 * Each line should have six fields, separated by '|' characters, where:
 * - UUID is a unique identifier (stored as a string in the file and parsed to uuid_t).
 * - name, email, and password are strings with defined maximum lengths.
 * - createdAt and updatedAt are UNIX timestamps (stored as long integers).
 * 
 * Memory for the array of User structs is allocated dynamically based on the number of 
 * records in the file. The caller is responsible for freeing this memory.
 * 
 * @param users      A pointer to a User* array that will be allocated and populated.
 * @param usersSize  A pointer to a size_t variable where the function will store the number
 *                   of users loaded.
 * 
 * @return int       Returns 0 on success, or a negative error code on failure:
 *                   - LOAD_USERS_FILE_OPEN_ERROR: Failed to open the users file.
 *                   - LOAD_USERS_MEMORY_ALLOCATION_ERROR: Failed to allocate memory for users.
 *                   - LOAD_USERS_DATA_FORMAT_ERROR: File data is not in the expected format.
 * 
 * 
 * Notes:
 * - UUIDs are read as strings and then converted to binary format using uuid_parse.
 * - If the function encounters any parsing errors, it will free the allocated memory
 *   and close the file before returning an error code.
 */
int loadUsers(User **users, size_t *usersSize);
#endif