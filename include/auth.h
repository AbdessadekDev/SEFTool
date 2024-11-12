#include <time.h>
#include <uuid/uuid.h>
#ifndef AUTH_H
#define AUTH_H

#define USER_ID_MAX 20
#define USER_NAME_MAX 50
#define USER_EMAIL_MAX 100
#define USER_PASSWORD_MAX 65

typedef enum {
    REGISTER_SUCCESS = 0,
    REGISTER_NULL_INPUT = -100,
    REGISTER_NOT_MATCH_PASS = -101,
    REGISTER_MEMORY_ALLOCATION_FAILED = -102,
    REGISTER_HASH_PASSWORD_ERR = -103,
    REGISTER_TOO_SHORT_NAME = -104,
    REGISTER_NON_ALPHANUMERIC_NAME = -105,
    REGISTER_REGEX_COMP_ERR = -106,
    REGISTER_INVALID_EMAIL = -107,
    REGISTER_TOO_SHORT_PASS = -108,
    REGISTER_MISSING_DIGIT_PASS = -109,
    REGISTER_MISSING_LOWERCASE_PASS = -110,
    REGISTER_MISSING_UPPERCASE_PASS = -111,
    REGISTER_MISSING_SPECIAL_PASS = -112,
    REGISTER_USERS_FILE_OPEN_ERROR = -113,
    REGISTER_USERS_UNABLE_TO_WRITE = -114

} RegisterUserCode;

typedef struct {
    char id[USER_ID_MAX];
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