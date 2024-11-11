#include <uuid/uuid.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "auth.h"
#include "utils.h"



int registerUser(char *name, char *email, char *password, char *confirmPassword) {
    if (name == NULL || email == NULL || password == NULL || confirmPassword == NULL) return -1;  // Null input check
    if (strcmp(password, confirmPassword) != 0) return -2;  // Password match check

    // Allocate memory for the new user and hashed password buffers
    User *newUser = malloc(sizeof(User));
    if (newUser == NULL) return -4;  // Memory allocation failed for User struct

    unsigned char *hashBytePassword = malloc(USER_PASSWORD_MAX);
    if (hashBytePassword == NULL) {
        free(newUser);
        return -4;
    }

    unsigned char *hashHexPassword = malloc(USER_PASSWORD_MAX * 2 + 1);
    if (hashHexPassword == NULL) {
        free(newUser);
        free(hashBytePassword);
        return -4;
    }

    uuid_t userId;
    uuid_generate(userId);  // Generate a unique ID for the user
    memcpy(newUser->id, userId, sizeof(uuid_t));

    // Copy and truncate user details
    strncpy(newUser->name, name, USER_NAME_MAX - 1);
    newUser->name[USER_NAME_MAX - 1] = '\0';  // Ensure null termination

    strncpy(newUser->email, email, USER_EMAIL_MAX - 1);
    newUser->email[USER_EMAIL_MAX - 1] = '\0';  // Ensure null termination

    // Hash the password
    int hashLen = hashPassword((unsigned char*)password, hashBytePassword);
    if (hashLen < 0) {  // Hashing error
        free(newUser);
        free(hashBytePassword);
        free(hashHexPassword);
        return -3;
    }

    // Convert hashed bytes to hex string
    byteToHex(hashBytePassword, hashLen, (char*)hashHexPassword);

    // Copy hashed password and ensure null termination
    strncpy(newUser->password, (char*)hashHexPassword, USER_PASSWORD_MAX - 1);
    newUser->password[USER_PASSWORD_MAX - 1] = '\0';

    // Set timestamps
    newUser->createdAt = time(NULL);
    newUser->updatedAt = time(NULL);

    // Free temporary buffers
    free(hashHexPassword);
    free(hashBytePassword);

    // Note: `newUser` should be freed by the caller after use
    return 0;
}