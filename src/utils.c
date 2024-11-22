// standards
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>

// openssl
#include <openssl/evp.h>
#include <openssl/rand.h>

// custom
#include "utils.h"
#include "auth.h"

int hashPassword(unsigned char *password, unsigned char *hashedPassword)
{
    EVP_MD_CTX *mdCtx;
    unsigned int hashLen;

    // Initialize the digest context
    if (!(mdCtx = EVP_MD_CTX_new()))
        return -1;

    // Initialize the SHA-256 hashing algorithm
    if (1 != EVP_DigestInit_ex(mdCtx, EVP_sha256(), NULL))
        return -2;

    // Feed the password data into the hashing function
    if (1 != EVP_DigestUpdate(mdCtx, password, strlen((char *)password)))
        return -3;

    // Retrieve the final hashed result
    if (1 != EVP_DigestFinal_ex(mdCtx, hashedPassword, &hashLen))
        return -4;

    // Free the digest context to avoid memory leaks
    EVP_MD_CTX_free(mdCtx);
    return (int)hashLen;
}

void byteToHex(unsigned char *bytes, int bytesLen, char *hex)
{
    for (int i = 0; i < bytesLen; i++)
        sprintf(&hex[i * 2], "%02x", bytes[i]); // Convert each byte to two hexadecimal characters
    hex[bytesLen * 2] = '\0';                   // Null-terminate the resulting string
}

void hexToBytes(const char *hex, unsigned char **bytes, size_t *length)
{
    size_t len = strlen(hex);
    *length = len / 2;
    *bytes = (unsigned char *)malloc(*length); // Allocate memory for the byte array

    for (size_t i = 0; i < *length; i++)
    {
        sscanf(hex + (i * 2), "%2hhx", &(*bytes)[i]); // Convert each pair of hex characters to a byte
    }
}

bool isFileExists(char *fileName)
{
    FILE *file = fopen(fileName, "r");
    if (file == NULL)
    {
        if (errno == 2)
            return false;
        return true;
    }
    fclose(file);
    return true;
}

int addLog(const char *level, const char *message, const char *fileName, const char *file, const char *function)
{

    if (level == NULL ||
        message == NULL ||
        fileName == NULL ||
        file == NULL ||
        function == NULL)
        return -501;

    FILE *logFile = fopen(fileName, "a");
    if (logFile == NULL)
        return -500;

    time_t lt = time(NULL);
    struct tm *pTm = localtime(&lt);

    fprintf(logFile, "%04d-%02d-%02d %02d:%02d:%02d [%s] (%s:%s) --- %s\n",
            pTm->tm_year + 1900, pTm->tm_mon + 1, pTm->tm_mday,
            pTm->tm_hour, pTm->tm_min, pTm->tm_sec, level, file, function, message);

    fclose(logFile);
    return 0;
}

void handleLoginUser(int result)
{
    switch (result)
    {
    case LOGIN_SUCCESS:
        printf("Login successful!\n");
        break;
    case LOGIN_NULL_INPUT:
        fprintf(stderr, "Error: Email or password is NULL.\n");
        break;
    case LOGIN_HASH_PASSWORD_ERR:
        fprintf(stderr, "Error: Failed to hash the password.\n");
        break;
    case LOGIN_INVALID_CREDENTIALS:
        fprintf(stderr, "Error: Invalid email or password.\n");
        break;
    case LOGIN_FILE_ERR:
        fprintf(stderr, "Error: Failed to create a session.\n");
        break;
    default:
        fprintf(stderr, "Error: Unknown error occurred.\n");
        fprintf(stderr, "[Hint] Don't forget to run: sfetool --init-keys\n");
        break;
    }
}

void handleRegisterResult(int result) {
    switch (result) {
        case REGISTER_SUCCESS:
            printf("Registration successful!\n");
            break;
        case REGISTER_NULL_INPUT:
            fprintf(stderr, "Error: One or more inputs are NULL.\n");
            break;
        case REGISTER_TOO_SHORT_NAME:
            fprintf(stderr, "Error: Name is too short.\n");
            break;
        case REGISTER_NON_ALPHANUMERIC_NAME:
            fprintf(stderr, "Error: Name contains non-alphanumeric characters.\n");
            break;
        case REGISTER_REGEX_COMP_ERR:
            fprintf(stderr, "Error: Regex compilation failed for email validation.\n");
            break;
        case REGISTER_INVALID_EMAIL:
            fprintf(stderr, "Error: Invalid email format.\n");
            break;
        case REGISTER_TOO_SHORT_PASS:
            fprintf(stderr, "Error: Password is too short.\n");
            break;
        case REGISTER_MISSING_DIGIT_PASS:
            fprintf(stderr, "Error: Password must contain at least one digit.\n");
            break;
        case REGISTER_MISSING_LOWERCASE_PASS:
            fprintf(stderr, "Error: Password must contain at least one lowercase letter.\n");
            break;
        case REGISTER_MISSING_UPPERCASE_PASS:
            fprintf(stderr, "Error: Password must contain at least one uppercase letter.\n");
            break;
        case REGISTER_MISSING_SPECIAL_PASS:
            fprintf(stderr, "Error: Password must contain at least one special character.\n");
            break;
        case REGISTER_NOT_MATCH_PASS:
            fprintf(stderr, "Error: Password and confirm password do not match.\n");
            break;
        case REGISTER_USERS_DUPLICATED_EMAIL:
            fprintf(stderr, "Error: Email is already registered.\n");
            break;
        case REGISTER_MEMORY_ALLOCATION_FAILED:
            fprintf(stderr, "Error: Memory allocation failed.\n");
            break;
        case REGISTER_HASH_PASSWORD_ERR:
            fprintf(stderr, "Error: Password hashing failed.\n");
            break;
        case REGISTER_USERS_FILE_OPEN_ERROR:
            fprintf(stderr, "Error: Unable to open the user file.\n");
            break;
        case REGISTER_USERS_UNABLE_TO_WRITE:
            fprintf(stderr, "Error: Unable to write to the user file.\n");
            break;
        default:
            fprintf(stderr, "Error: An unknown error occurred.\n");
            break;
    }
}

void disableEcho() {
    struct termios t;
    tcgetattr(STDIN_FILENO, &t);  // Get current terminal settings
    t.c_lflag &= ~ECHO;           // Disable echo
    tcsetattr(STDIN_FILENO, TCSANOW, &t);  // Apply settings immediately
}

void enableEcho() {
    struct termios t;
    tcgetattr(STDIN_FILENO, &t);  // Get current terminal settings
    t.c_lflag |= ECHO;            // Enable echo
    tcsetattr(STDIN_FILENO, TCSANOW, &t);  // Apply settings immediately
}