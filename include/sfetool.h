#include "auth.h"
#ifndef SFETOOL_H
#define SFETOOL_H

#define USERS_FILE "data/users.dat"
#define USER_INFO_MAX 300
#define SFETOOL_KEY_LEN 16

typedef enum {
    LOAD_USERS_SUCCESS = 0,
    LOAD_USERS_FILE_OPEN_ERROR = -1,
    LOAD_USERS_MEMORY_ALLOCATION_ERROR = -2,
    LOAD_USERS_DATA_FORMAT_ERROR = -3,
} LoadUsersError;

typedef enum {
    SAVE_USERS_SUCCESS = 0,
    SAVE_USERS_FILE_OPEN_ERROR = -1,
    SAVE_USERS_UNABLE_TO_WRITE = -2
} SaveUserError;

typedef enum {
    ENCRYPTFILE_SUCCESS = 0,
    ENCRYPTFILE_UNABLE_TO_OPEN_FILE = -1,
    ENCRYPTFILE_UNABLE_TO_OPEN_FILE_COUNT = -8,
    ENCRYPTFILE_FIALS_TO_INI_CTX = -2,
    ENCRYPTFILE_FIALS_TO_INI_ENC = -3,
    ENCRYPTFILE_MEMORY_ALLOCATION_ERR = -4,
    ENCRYPTFILE_ENCRYPTION_ERR = -5,
    ENCRYPTFILE_UNABLE_TO_REMOVE_ACTUAL_FILE = -700
} EncryptFileCode;

typedef enum {
    DECRYPTFILE_SUCCESS = 0,
    DECRYPTFILE_UNABLE_TO_OPEN_FILE =  -600,
    DECRYPTFILE_UNABLE_TO_OPEN_OUTPUT = -601,
    DECRYPTFILE_FAIL_TO_INIT_CTX = -602,
    DECRYPTFILE_FAIL_TO_INIT_DEC = 603,
    DECRYPTFILE_DECRYPTION_ERR = -604
} DecryptFileCode;

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

/**
 * saveUser - Appends a single user to the users file.
 * 
 * This function writes a user's data to a file specified by the USERS_FILE macro. 
 * The user's information is stored in the following format:
 * 
 *     UUID|name|email|password|createdAt|updatedAt
 * 
 * The fields are separated by '|' characters. The UUID is written as a string (not binary),
 * and the UNIX timestamps for `createdAt` and `updatedAt` are stored as long integers.
 * 
 * The file is opened in append mode (`"a"`), meaning the user's data will be added to the 
 * end of the file. If the file does not exist, it will be created.
 * 
 * @param user  The User struct whose data is to be saved to the file.
 * 
 * @return int  Returns `SAVE_USERS_SUCCESS` if the user data was successfully written 
 *              to the file, or a negative error code on failure:
 *              - `SAVE_USERS_FILE_OPEN_ERROR`: Failed to open the users file for appending.
 *              - `SAVE_USERS_UNABLE_TO_WRITE`: Failed to write user data to the file.
 * 
 **/
int saveUser(User *user);
/**
 * 
 * Encrypts the contents of a text file line by line using AES-128-CBC encryption
 * and writes the encrypted lines to a new file with the .enc extension.
 * 
 * @param filename The name of the file to be encrypted.
 * @param key The encryption key used for AES-128-CBC encryption.
 * @param iv The initialization vector (IV) used for AES-128-CBC encryption.
 * 
 * @return
 * 
 * - `ENCRYPTFILE_SUCCESS` if encryption is successful.
 * - Various error codes indicating issues (e.g., file access, encryption context setup, memory allocation).
 */
int encryptFile(const char *filename, unsigned char *key, unsigned char *iv);

/**
 * Decrypts a file with an .enc extension, assuming it was encrypted with AES-128-CBC,
 * and writes the decrypted content to a new file without the .enc extension.
 * 
 * @param encryptedFileName The name of the encrypted file to be decrypted.
 * @param key The decryption key used for AES-128-CBC decryption.
 * @param iv The initialization vector (IV) used for AES-128-CBC decryption.
 * @return
 * - `DECRYPTFILE_SUCCESS` if decryption is successful.
 * - Various error codes indicating issues (e.g., file access, decryption context setup).
 */
int decryptFile(const char *encryptedFileName, unsigned char *key, unsigned char *iv);

void genKey(char *name);

#endif