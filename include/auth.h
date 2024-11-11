#include <time.h>
#include <uuid/uuid.h>
#ifndef AUTH_H
#define AUTH_H

#define USER_NAME_MAX 50
#define USER_EMAIL_MAX 100
#define USER_PASSWORD_MAX 65

typedef struct User {
    uuid_t id;
    char name[USER_NAME_MAX];
    char email[USER_EMAIL_MAX];
    char password[USER_PASSWORD_MAX];
    time_t createdAt;
    time_t updatedAt;
} User;

/**
 * Registers a new user.
 * 
 * @param name            User's name (input).
 * @param email           User's email address (input).
 * @param password        User's password (input).
 * @param confirmPassword Confirmation of the password (input).
 * @return                0 on success, or a negative error code on failure.
 */
int registerUser(char *name, char *email, char *password, char *confirmPassword);

#endif