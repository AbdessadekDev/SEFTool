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
    if (isEmailExists(email) != 0) return REGISTER_USERS_DUPLICATED_EMAIL;

    // Allocate memory for the new user and hashed password buffers
    User *newUser = malloc(sizeof(User));
    if (newUser == NULL) return REGISTER_MEMORY_ALLOCATION_FAILED;  // Memory allocation failed for User struct

    unsigned char userId[USER_ID_MAX];
    uuid_generate(userId);  // Generate a unique ID for the user

    char userIdHex[USER_ID_MAX * 2 + 1];
    byteToHex(userId, sizeof(userId), userIdHex);
    strncpy(newUser->id, userIdHex, USER_ID_MAX * 2 + 1);
    newUser->id[USER_ID_MAX * 2] = '\0';

    // Copy and truncate user details
    strncpy(newUser->name, name, USER_NAME_MAX);
    newUser->name[USER_NAME_MAX - 1] = '\0';  // Ensure null termination

    strncpy(newUser->email, email, USER_EMAIL_MAX );
    newUser->email[USER_EMAIL_MAX - 1] = '\0';  // Ensure null termination

    unsigned char hashBytePassword[USER_PASSWORD_MAX] = {0};
    unsigned char hashHexPassword[USER_PASSWORD_MAX * 2 + 1] = {0};

    // Hash the password
    int hashLen = hashPassword((unsigned char*)password, hashBytePassword);
    if (hashLen < 0) {  // Hashing error
        free(newUser);
        return REGISTER_HASH_PASSWORD_ERR;
    }

    // Convert hashed bytes to hex string
    byteToHex(hashBytePassword, hashLen, (char*)hashHexPassword);

    // Copy hashed password and ensure null termination
    strncpy(newUser->password, (char*)hashHexPassword, USER_PASSWORD_MAX * 2 + 1);
    newUser->password[USER_PASSWORD_MAX * 2] = '\0';

    // Set timestamps
    newUser->createdAt = time(NULL);
    newUser->updatedAt = time(NULL);

    // Save in USERS_FILE
    int saveCode = saveUser(newUser); 
    if (saveCode == SAVE_USERS_FILE_OPEN_ERROR) {
        free(newUser);
        return REGISTER_USERS_FILE_OPEN_ERROR;
    }
    if (saveCode == SAVE_USERS_UNABLE_TO_WRITE) {
        free(newUser);
        return REGISTER_USERS_UNABLE_TO_WRITE;
    }
    size_t messageLength = snprintf(NULL, 0, "%s has been registered", newUser->email) + 1;
    char *message = malloc(messageLength);

    snprintf(message, messageLength, "%s has been registered", newUser->email);
    message[messageLength - 1] = '\0';

    addLog("INFO", message, "data/auth.log", __FILE__, "registerUser");

    // Free temporary buffers
    free(message);
    free(newUser);

    return REGISTER_SUCCESS;
}

int loginUser(const char *email, const char *password) {
    if (email == NULL || password == NULL) return LOGIN_NULL_INPUT;
    
    unsigned char hashHexPassword[USER_PASSWORD_MAX * 2 + 1];
    unsigned char hashBytePassword[USER_PASSWORD_MAX];
    int hashLength = hashPassword((unsigned char*)password, hashBytePassword);
    if (hashLength < 0 ) return LOGIN_HASH_PASSWORD_ERR;

     // Convert hashed bytes to hex string
    byteToHex(hashBytePassword, hashLength, (char*)hashHexPassword);

    User *user = getUserInfo(email);
    if (!user) {
        free(user);
        return LOGIN_INVALID_CREDENTIALS;
    }

    if (strcmp(user->password, (char *)hashHexPassword) != 0) {
        free(user);
        return LOGIN_INVALID_CREDENTIALS;
    } 

    if (createSession(email) != SUCCESS) {
        free(user);
        return LOGIN_FILE_ERR;
    }

    int msgLength = snprintf(NULL, 0, "%s has been logged in", email);
    char *msg = malloc(msgLength);

    snprintf(msg, msgLength, "%s has been logged in", email);

    addLog("[INFO]", msg, AUTH_LOG_FILE, __FILE__, __func__ );

    free(user);
    free(msg);
    return LOGIN_SUCCESS;
    
}


int changePassword(const char *oldPassword, const char *newPassword) {
    // Password Roles
    int minPasswordLen = 8;
    ValidationRule passRoles[] = {
        {minLength, &minPasswordLen, TOO_SHORT},
        {isPassword, NULL, MISSING_DIGIT},
        {isPassword, NULL, MISSING_LOWERCASE},
        {isPassword, NULL, MISSING_UPPERCASE},
        {isPassword, NULL, MISSING_SPECIAL},
    };

    ValidationResult validPassword = validate(newPassword, passRoles, 5);

    if (validPassword == TOO_SHORT) return REGISTER_TOO_SHORT_PASS;
    if (validPassword == MISSING_DIGIT) return REGISTER_MISSING_DIGIT_PASS;
    if (validPassword == MISSING_LOWERCASE) return REGISTER_MISSING_LOWERCASE_PASS;
    if (validPassword == MISSING_UPPERCASE) return REGISTER_MISSING_UPPERCASE_PASS;
    if (validPassword == MISSING_SPECIAL) return REGISTER_MISSING_SPECIAL_PASS;

    FILE *loginFile = fopen(LOGIN_FILE, "rb");
    if (loginFile == NULL) return -2;

    size_t bytesTokenlength = USER_EMAIL_MAX + 21 + EVP_CIPHER_block_size(EVP_aes_128_cbc());
    unsigned char bytesToken = malloc(bytesTokenlength);
    unsigned char token[USER_EMAIL_MAX + 21];

    if (fread(token, 1, USER_EMAIL_MAX + 21, loginFile) < 0) {
        fclose(loginFile);
        return -6;
    }

    return 0;
}