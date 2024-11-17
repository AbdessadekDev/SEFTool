#include <stdint.h> // For consistent data types
#include "auth.h"
#ifndef SFETOOL_H
#define SFETOOL_H


#define USERS_FILE "data/users.dat"
#define LOGIN_FILE "data/login.enc"
#define USER_INFO_MAX 300
#define SFETOOL_KEY_LEN 16 // AES-128 requires a 16-byte key

// Error Codes for Loading Users
typedef enum {
    LOAD_USERS_SUCCESS = 0,
    LOAD_USERS_FILE_OPEN_ERROR = -1,
    LOAD_USERS_MEMORY_ALLOCATION_ERROR = -2,
    LOAD_USERS_DATA_FORMAT_ERROR = -3,
} LoadUsersError;

// Error Codes for Saving Users
typedef enum {
    SAVE_USERS_SUCCESS = 0,
    SAVE_USERS_FILE_OPEN_ERROR = -1,
    SAVE_USERS_UNABLE_TO_WRITE = -2
} SaveUserError;

// Error Codes for Encrypting Files
typedef enum {
    ENCRYPTFILE_SUCCESS = 0,
    ENCRYPTFILE_FILE_ERROR = -100,           // General file access error
    ENCRYPTFILE_CONTEXT_ERROR = -101,        // Encryption context initialization error
    ENCRYPTFILE_MEMORY_ERROR = -102,         // Memory allocation error
    ENCRYPTFILE_ENCRYPTION_ERROR = -103,     // Error during the encryption process
    ENCRYPTFILE_FILE_REPLACEMENT_ERROR = -104 // Unable to remove original file after encryption
} EncryptFileCode;

// Error Codes for Decrypting Files
typedef enum {
    DECRYPTFILE_SUCCESS = 0,
    DECRYPTFILE_FILE_ERROR = -200,           // General file access error
    DECRYPTFILE_CONTEXT_ERROR = -201,        // Decryption context initialization error
    DECRYPTFILE_DECRYPTION_ERROR = -202      // Error during the decryption process
} DecryptFileCode;

typedef enum {
    ENCRYPT_SUCCESS,
    ENCRYPT_INIT_CXT_ERR,
    ENCRYPT_INIT_ENCRYPTION,
    ENCRYPT_UPDATE_ENCRYPTION,
    ENCRYPT_FINAL_ENCRYPTION,
} EncryptCode;

typedef enum {
    SUCCESS = 0,
    ERR_FILE_OPEN_FAILED = -100,
    ERR_MEMORY_ALLOCATION_FAILED = -102,
    ERR_SFETOOL_KEY_OR_IV_MISSING = -12,
    ERR_KEY_IV_ALLOCATION_FAILED = -103,
    ERR_INVALID_KEY_IV_LENGTH = -104,
    ERR_ENCRYPTION_FAILED = -13,
    ERR_TOKEN_CREATION_FAILED = -101,
    ERR_FILE_READ_FAILED = -105
} StatusCode;

typedef enum {
    SUCCESS = 0,
    FILE_OPEN_ERROR,
    FILE_WRITE_ERROR,
    FILE_READ_ERROR,
    FILENAME_NOT_FOUND
} StatusCodeCSV;

/**
 * Loads user data from a file and populates an array of User structs.
 *
 * @param users       A pointer to a User* array to be allocated and populated.
 * @param usersSize   A pointer to a size_t variable where the number of users will be stored.
 *
 * @return            LOAD_USERS_SUCCESS (0) on success, or a negative error code:
 *                    - LOAD_USERS_FILE_OPEN_ERROR
 *                    - LOAD_USERS_MEMORY_ALLOCATION_ERROR
 *                    - LOAD_USERS_DATA_FORMAT_ERROR
 */
int loadUsers(User ***users, size_t *usersSize);

/**
 * Appends a single user to the users file.
 *
 * @param user        The User struct to save.
 *
 * @return            SAVE_USERS_SUCCESS (0) if successful, or a negative error code:
 *                    - SAVE_USERS_FILE_OPEN_ERROR
 *                    - SAVE_USERS_UNABLE_TO_WRITE
 */
int saveUser(User *user);

/**
 * Encrypts a text file line by line using AES-128-CBC encryption.
 * The output is written to a new file with the .enc extension.
 *
 * @param filename    The name of the file to be encrypted.
 * @param key         A 16-byte encryption key (AES-128).
 * @param iv          The 16-byte initialization vector (IV) for AES-128-CBC.
 *
 * @return            ENCRYPTFILE_SUCCESS (0) if successful, or a negative error code:
 *                    - ENCRYPTFILE_FILE_ERROR
 *                    - ENCRYPTFILE_CONTEXT_ERROR
 *                    - ENCRYPTFILE_MEMORY_ERROR
 *                    - ENCRYPTFILE_ENCRYPTION_ERROR
 *                    - ENCRYPTFILE_FILE_REPLACEMENT_ERROR
 */
int encryptFile(const char *filename, const unsigned char *key, const unsigned char *iv);

/**
 * Decrypts an encrypted file with an .enc extension using AES-128-CBC.
 * The decrypted content is written to a new file without the .enc extension.
 *
 * @param encryptedFileName   The name of the encrypted file.
 * @param key                 A 16-byte decryption key (AES-128).
 * @param iv                  The 16-byte initialization vector (IV) for AES-128-CBC.
 *
 * @return                    DECRYPTFILE_SUCCESS (0) if successful, or a negative error code:
 *                            - DECRYPTFILE_FILE_ERROR
 *                            - DECRYPTFILE_CONTEXT_ERROR
 *                            - DECRYPTFILE_DECRYPTION_ERROR
 */
int decryptFile(const char *encryptedFileName, const unsigned char *key, const unsigned char *iv);

/**
 * setupKeys - Generates and outputs an encryption key and IV for initial program configuration.
 * 
 * This function generates a secure 128-bit AES encryption key and IV using cryptographic 
 * random bytes. It outputs the key and IV as shell commands to export them as environment 
 * variables (`SFETOOL_KEY` and `SFETOOL_IV`). This setup is required before using encryption 
 * features in the program.
 * 
 * Usage:
 *   Run this command once during setup:
 *   $ ./program_name setup-encryption
 *   This will print:
 *   export SFETOOL_KEY=<generated_key>
 *   export SFETOOL_IV=<generated_iv>
 */
void setupKeys();

/**
 * @brief Check if the given email exists in USERS_FILE.
 * 
 * @param email the email looking for
 * 
 * @return 
 *          - 1 if the email is already exists.
 *          - 0 if the email isn't exists.
 *          - a nigative number if an error occur during load users.
 */
int isEmailExists(const char *email);
/**
 * Fetches the user information based on the provided email address.
 * 
 * @param email A string representing the user's email address to fetch the user information.
 * 
 * @return A pointer to a `User` structure containing the user's details, or `NULL` if no user is found.
 * 
 */
User *getUserInfo(const char *email);

/**
 * Creates a session for the user with the given email.
 * 
 * @param email The email address of the user to create a session for.
 * 
 * @return `0` on success (session created), a nigative number where it's fails.
 */
int createSession(const char *email);

/**
 * Checks if there is an active session.
 * 
 * @return `0` on success, a nigative number where it's fails.
 */
int checkSession();

/**
 * Encrypts the input data using the specified key and initialization vector (IV).
 * 
 * @param input (unsigned char *): A pointer to the input data to be encrypted.
 * @param inputLength (int): The length of the input data in bytes.
 * @param output (unsigned char *): A pointer to the memory where the encrypted data will be stored.
 * @param key (unsigned char *): The encryption key.
 * @param iv (unsigned char *): The initialization vector used for encryption.
 * 
 * @return 0 on successful encryption, nigative code number on fails.
 */
int encrypt(unsigned char *input, int inputLength, unsigned char *output, unsigned char *key, unsigned char *iv);
int decrypt(unsigned char *input, int inputLength, unsigned char *output, unsigned char *key, unsigned char *iv);

int computeFileHash(const char *filename, unsigned char *hash_out, unsigned int *hash_len);
void printHash(unsigned char *hash, unsigned int hash_length);

/**
 * append a record to the CSV file
 */
int appendToCsv(const char *csvFileName, const char *fileName, const char *hash);

/**
 * Read the hash for a given filename from the CSV file
 */
int readFromCsv(const char *csvFileName, const char *fileName, char *hashBuffer, size_t bufferSize);

#endif
