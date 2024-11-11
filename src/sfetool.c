// standard headers
#include <stdio.h>
#include <stdlib.h>
#include <uuid/uuid.h>
#include <time.h>
#include <string.h>


#include "auth.h"
#include "sfetool.h"

int loadUsers(User **users, size_t *usersSize) {
    char buffer[USER_INFO_MAX];

    FILE *pUsersFile = fopen(USERS_FILE, "r");
    if (pUsersFile == NULL) return LOAD_USERS_FILE_OPEN_ERROR;

    // Count lines to determine number of users
    size_t count = 0;
    while (fgets(buffer, USER_INFO_MAX, pUsersFile)) {
        count++;
    }
    fseek(pUsersFile, 0, SEEK_SET);

    *users = malloc(count * sizeof(User));
    if (*users == NULL) {
        fclose(pUsersFile);
        return LOAD_USERS_MEMORY_ALLOCATION_ERROR;
    }
    *usersSize = count;

    // Read each user record
    size_t index = 0;
    while (fgets(buffer, USER_INFO_MAX, pUsersFile) && index < *usersSize) {
        char userIdStr[37];  // UUID string is 36 chars + null terminator
        char name[USER_NAME_MAX];
        char email[USER_EMAIL_MAX];
        char password[USER_PASSWORD_MAX];
        time_t createdAt;
        time_t updatedAt;

        // Read each field, expecting the UUID to be in string format
        int matched = sscanf(buffer, "%36s|%s|%s|%s|%ld|%ld\n", userIdStr, name, email, password, &createdAt, &updatedAt);
        if (matched != 6) {
            fclose(pUsersFile);
            free(*users);
            return LOAD_USERS_DATA_FORMAT_ERROR;
        }

        // Convert the UUID string to binary format and store it in the user struct
        if (uuid_parse(userIdStr, (*users)[index].id) != 0) {
            fclose(pUsersFile);
            free(*users);
            return LOAD_USERS_DATA_FORMAT_ERROR;
        }

        // Copy other fields
        strncpy((*users)[index].name, name, USER_NAME_MAX);
        (*users)[index].name[USER_NAME_MAX - 1] = '\0';

        strncpy((*users)[index].email, email, USER_EMAIL_MAX);
        (*users)[index].email[USER_EMAIL_MAX - 1] = '\0';

        strncpy((*users)[index].password, password, USER_PASSWORD_MAX);
        (*users)[index].password[USER_PASSWORD_MAX - 1] = '\0';

        (*users)[index].createdAt = createdAt;
        (*users)[index].updatedAt = updatedAt;

        index++;
    }

    fclose(pUsersFile);
    return LOAD_USERS_SUCCESS;
}