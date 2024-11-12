#include <uuid/uuid.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "auth.h"
#include "utils.h"
#include "validation_utils.h"
#include "sfetool.h"


int registerUser(char *name, char *email, char *password, char *confirmPassword) {
    if (name == NULL || email == NULL || password == NULL || confirmPassword == NULL) return REGISTER_NULL_INPUT;  // Null input check
    
    // Name roles
    int minNameLen = 3;
    ValidationRule nameRoles[] = {
        {minLength, &minNameLen, TOO_SHORT},
        {isAlphaNumeric, NULL, NON_ALPHANUMERIC_FOUND},
    };

    // Email Roles
    ValidationRule emailRoles[] = {
        {isEmail, NULL, REGEX_COMPILATION_FAILED},
        {isEmail, NULL, EMAIL_FORMAT_INVALID}
    };

    // Password Roles
    int minPasswordLen = 8;
    ValidationRule passRoles[] = {
        {minLength, &minPasswordLen, TOO_SHORT},
        {isPassword, NULL, MISSING_DIGIT},
        {isPassword, NULL, MISSING_LOWERCASE},
        {isPassword, NULL, MISSING_UPPERCASE},
        {isPassword, NULL, MISSING_SPECIAL},
    };
    
    ValidationResult validName = validate(name, nameRoles, 2);
    ValidationResult validEmail = validate(email, emailRoles, 2);
    ValidationResult validPassword = validate(password, passRoles, 5);

    if (validName == TOO_SHORT) return REGISTER_TOO_SHORT_NAME;
    if (validName == NON_ALPHANUMERIC_FOUND) return REGISTER_NON_ALPHANUMERIC_NAME;

    if (validEmail == REGEX_COMPILATION_FAILED) return REGISTER_REGEX_COMP_ERR;
    if (validEmail == EMAIL_FORMAT_INVALID) return REGISTER_INVALID_EMAIL;

    if (validPassword == TOO_SHORT) return REGISTER_TOO_SHORT_PASS;
    if (validPassword == MISSING_DIGIT) return REGISTER_MISSING_DIGIT_PASS;
    if (validPassword == MISSING_LOWERCASE) return REGISTER_MISSING_LOWERCASE_PASS;
    if (validPassword == MISSING_UPPERCASE) return REGISTER_MISSING_UPPERCASE_PASS;
    if (validPassword == MISSING_SPECIAL) return REGISTER_MISSING_SPECIAL_PASS;


    if (strcmp(password, confirmPassword) != 0) return REGISTER_NOT_MATCH_PASS;  // Password match check

    // Allocate memory for the new user and hashed password buffers
    User *newUser = malloc(sizeof(User));
    if (newUser == NULL) return REGISTER_MEMORY_ALLOCATION_FAILED;  // Memory allocation failed for User struct

    unsigned char *hashBytePassword = malloc(USER_PASSWORD_MAX);
    if (hashBytePassword == NULL) {
        free(newUser);
        return REGISTER_MEMORY_ALLOCATION_FAILED;
    }

    unsigned char *hashHexPassword = malloc(USER_PASSWORD_MAX * 2 + 1);
    if (hashHexPassword == NULL) {
        free(newUser);
        free(hashBytePassword);
        return REGISTER_MEMORY_ALLOCATION_FAILED;
    }

    unsigned char userId[USER_ID_MAX];
    uuid_generate(userId);  // Generate a unique ID for the user

    char *userIdHex = malloc(USER_ID_MAX);
    byteToHex(userId, sizeof(userId), userIdHex);
    strncpy(newUser->id, userIdHex, USER_ID_MAX);
    newUser->id[USER_ID_MAX - 1] = '\0';

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
        return REGISTER_HASH_PASSWORD_ERR;
    }

    // Convert hashed bytes to hex string
    byteToHex(hashBytePassword, hashLen, (char*)hashHexPassword);

    // Copy hashed password and ensure null termination
    strncpy(newUser->password, (char*)hashHexPassword, USER_PASSWORD_MAX - 1);
    newUser->password[USER_PASSWORD_MAX - 1] = '\0';

    // Set timestamps
    newUser->createdAt = time(NULL);
    newUser->updatedAt = time(NULL);

    int saveCode = saveUser(newUser); 
    if (saveCode == SAVE_USERS_FILE_OPEN_ERROR) return REGISTER_USERS_FILE_OPEN_ERROR;
    if (saveCode == SAVE_USERS_UNABLE_TO_WRITE) return REGISTER_USERS_UNABLE_TO_WRITE;   

    // Free temporary buffers
    free(hashHexPassword);
    free(hashBytePassword);
    free(userIdHex);
    free(newUser);

    return REGISTER_SUCCESS;
}