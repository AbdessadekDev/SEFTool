#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "sfetool.h"
#include "utils.h"

// Load user data from file and populate the users array
int loadUsers(User ***users, size_t *usersSize) {
    char buffer[USER_INFO_MAX];
    *usersSize = 0; // Initialize usersSize

    FILE *pUsersFile = fopen(USERS_FILE, "r");
    if (pUsersFile == NULL) return LOAD_USERS_FILE_OPEN_ERROR;

    // Count lines to determine number of users
    size_t count = 0;
    while (fgets(buffer, USER_INFO_MAX, pUsersFile)) {
        count++;
    }
    fseek(pUsersFile, 0, SEEK_SET);

    User **temp = malloc(count * sizeof(User *)); // Allocate array of pointers
    if (temp == NULL) {
        fclose(pUsersFile);
        return LOAD_USERS_MEMORY_ALLOCATION_ERROR;
    }
    *users = temp;

    size_t index = 0;
    while (fgets(buffer, USER_INFO_MAX, pUsersFile)) {
        (*users)[index] = malloc(sizeof(User));
        if ((*users)[index] == NULL) {
            fclose(pUsersFile);
            cleanupUsers(*users, index);
            return LOAD_USERS_MEMORY_ALLOCATION_ERROR;
        }
        memset((*users)[index], 0, sizeof(User));

        char userId[USER_ID_MAX] = {0};
        char name[USER_NAME_MAX] = {0};
        char email[USER_EMAIL_MAX] = {0};
        char password[USER_PASSWORD_MAX] = {0};
        time_t createdAt;
        time_t updatedAt;


        int matched = sscanf(buffer, "%33[^|]|%50[^|]|%100[^|]|%65[^|]|%ld|%ld", userId, name, email, password, &createdAt, &updatedAt);
        if (matched != 6) {
            fclose(pUsersFile);
            cleanupUsers(*users, index + 1);
            return LOAD_USERS_DATA_FORMAT_ERROR;
        }

        strncpy((*users)[index]->id, userId, USER_ID_MAX * 2 + 1);
        (*users)[index]->id[USER_ID_MAX * 2] = '\0';

        strncpy((*users)[index]->name, name, USER_NAME_MAX);
        (*users)[index]->name[USER_NAME_MAX - 1] = '\0';

        strncpy((*users)[index]->email, email, USER_EMAIL_MAX);
        (*users)[index]->email[USER_EMAIL_MAX - 1] = '\0';

        strncpy((*users)[index]->password, password, USER_PASSWORD_MAX * 2 + 1);
        (*users)[index]->password[USER_PASSWORD_MAX * 2] = '\0';

        (*users)[index]->createdAt = createdAt;
        (*users)[index]->updatedAt = updatedAt;

        index++;
    }

    fclose(pUsersFile);
    *usersSize = index; // Update the actual number of users loaded
    return LOAD_USERS_SUCCESS;
}

void cleanupUsers(User **users, size_t usersSize) {
    for (size_t i = 0; i < usersSize; i++) 
        free(users[i]);
    free(users);
    users = NULL;
}


// Append a single user to the users file
int saveUser(User *user) {
    if (!isFileExists("data"))
        if (mkdir("data", 0777) == -1) 
            return SAVE_USERS_FILE_OPEN_ERROR;

    FILE *file = fopen(USERS_FILE, "a");
    if (!file) return SAVE_USERS_FILE_OPEN_ERROR;
            
    if (fprintf(file, "%s|%s|%s|%s|%ld|%ld\n",
            user->id,
            user->name,
            user->email,
            user->password,
            user->createdAt,
            user->updatedAt
        ) < 6) {
        fclose(file);
        return SAVE_USERS_UNABLE_TO_WRITE;
    }
    fclose(file);
    return SAVE_USERS_SUCCESS;
}

// Encrypts a file using AES-128-CBC and outputs it with a .enc extension
int encryptFile(const char *filename, const unsigned char *key, const unsigned char *iv) {
    FILE *inputFile = fopen(filename, "rb");
    if (!inputFile) return ENCRYPTFILE_FILE_ERROR;

    char encFilename[256];
    snprintf(encFilename, sizeof(encFilename), "%s.enc", filename);

    FILE *outputFile = fopen(encFilename, "wb");
    if (!outputFile) {
        fclose(inputFile);
        return ENCRYPTFILE_FILE_ERROR;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(inputFile);
        fclose(outputFile);
        return ENCRYPTFILE_CONTEXT_ERROR;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(inputFile);
        fclose(outputFile);
        return ENCRYPTFILE_CONTEXT_ERROR;
    }

    unsigned char buffer[1024];
    unsigned char cipherText[1024 + EVP_CIPHER_block_size(EVP_aes_128_cbc())];
    int bytesRead, cipherTextLen;

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), inputFile)) > 0) {
        if (EVP_EncryptUpdate(ctx, cipherText, &cipherTextLen, buffer, bytesRead) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(inputFile);
            fclose(outputFile);
            return ENCRYPTFILE_ENCRYPTION_ERROR;
        }
        fwrite(cipherText, 1, cipherTextLen, outputFile);
    }

    if (EVP_EncryptFinal_ex(ctx, cipherText, &cipherTextLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(inputFile);
        fclose(outputFile);
        return ENCRYPTFILE_ENCRYPTION_ERROR;
    }
    fwrite(cipherText, 1, cipherTextLen, outputFile);

    EVP_CIPHER_CTX_free(ctx);
    fclose(inputFile);
    fclose(outputFile);

    // Optionally, remove the original file after successful encryption
    // if (remove(filename) != 0) return ENCRYPTFILE_FILE_REPLACEMENT_ERROR;

    int msgLength = snprintf(NULL, 0, "%s has been encrypted", filename);
    char *msg = malloc(msgLength);

    snprintf(msg, msgLength, "%s has been encrypted", filename);

    addLog("[INFO]", msg, ENCRYPTION_LOG_FILE, __FILE__, __func__ );
    free(msg);

    return ENCRYPTFILE_SUCCESS;
}

// Decrypts a .enc file using AES-128-CBC and outputs it without the .enc extension
int decryptFile(const char *encryptedFileName, const unsigned char *key, const unsigned char *iv) {
    FILE *inputFile = fopen(encryptedFileName, "rb");
    if (!inputFile) return DECRYPTFILE_FILE_ERROR;

    char decFilename[256];
    strncpy(decFilename, encryptedFileName, strlen(encryptedFileName) - 4);
    decFilename[strlen(encryptedFileName) - 4] = '\0';

    FILE *outputFile = fopen(decFilename, "wb");
    if (!outputFile) {
        fclose(inputFile);
        return DECRYPTFILE_FILE_ERROR;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(inputFile);
        fclose(outputFile);
        return DECRYPTFILE_CONTEXT_ERROR;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(inputFile);
        fclose(outputFile);
        return DECRYPTFILE_CONTEXT_ERROR;
    }

    unsigned char buffer[1024];
    unsigned char plainText[1024];
    int bytesRead, plainTextLen;

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), inputFile)) > 0) {
        if (EVP_DecryptUpdate(ctx, plainText, &plainTextLen, buffer, bytesRead) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(inputFile);
            fclose(outputFile);
            addLog("[ERR]", "DECRYPTFILE_DECRYPTION_ERROR", ENCRYPTION_LOG_FILE,__FILE__, __func__ );
            return DECRYPTFILE_DECRYPTION_ERROR;
        }
        fwrite(plainText, 1, plainTextLen, outputFile);
    }

    if (EVP_DecryptFinal_ex(ctx, plainText, &plainTextLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(inputFile);
        fclose(outputFile);
        return DECRYPTFILE_DECRYPTION_ERROR;
    }
    fwrite(plainText, 1, plainTextLen, outputFile);

    EVP_CIPHER_CTX_free(ctx);
    fclose(inputFile);
    fclose(outputFile);

    int msgLength = snprintf(NULL, 0, "%s has been decrypted", encryptedFileName);
    char *msg = malloc(msgLength);

    snprintf(msg, msgLength, "%s has been decrypted", encryptedFileName);

    addLog("[INFO]", msg, ENCRYPTION_LOG_FILE, __FILE__, __func__ );
    free(msg);

    return DECRYPTFILE_SUCCESS;
}

int encrypt(unsigned char *input, int inputLength, unsigned char *output, unsigned char *key, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx;
    int outputLength1 = 0, outputLength2 = 0;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) return ENCRYPT_INIT_CXT_ERR;

    // Initialize encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return ENCRYPT_INIT_ENCRYPTION;
    }

    // Provide the data to be encrypted
    if (1 != EVP_EncryptUpdate(ctx, output, &outputLength1, input, inputLength)) {
        EVP_CIPHER_CTX_free(ctx);
        return ENCRYPT_UPDATE_ENCRYPTION;
    }
    outputLength2 = outputLength1;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, output + outputLength1, &outputLength1)) {
        EVP_CIPHER_CTX_free(ctx);
        return ENCRYPT_FINAL_ENCRYPTION;
    }
    outputLength2 += outputLength1;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    return outputLength2;
}

int decrypt(unsigned char *input, int inputLength, unsigned char *output, unsigned char *key, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx;
    int outputLength1 = 0, outputLength2 = 0;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) return ENCRYPT_INIT_CXT_ERR;

    // Initialize decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return ENCRYPT_INIT_ENCRYPTION;
    }

    // Provide the data to be decrypted
    if (1 != EVP_DecryptUpdate(ctx, output, &outputLength1, input, inputLength)) {
        EVP_CIPHER_CTX_free(ctx);
        return ENCRYPT_UPDATE_ENCRYPTION;
    }
    outputLength2 = outputLength1;

    // Finalize decryption
    if (1 != EVP_DecryptFinal_ex(ctx, output + outputLength1, &outputLength1)) {
        EVP_CIPHER_CTX_free(ctx);
        return ENCRYPT_FINAL_ENCRYPTION;
    }
    outputLength2 += outputLength1;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    return outputLength2;
}


void setupKeys() {
    unsigned char key[SFETOOL_KEY_LEN];
    unsigned char iv[SFETOOL_KEY_LEN];

    if (RAND_bytes(key, sizeof(key)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1) {
        fprintf(stderr, "Error generating random bytes for key or IV.\n");
        return;
    }

    printf("Keys generated successfully.\n");
    printf("To set up the environment variables, please run the following commands in your terminal:\n");
    printf("\n");

    printf("\033[0;33mexport\033[0m \033[0;35mSFETOOL_KEY\033[0m=\033[0;32m");
    for (int i = 0; i < SFETOOL_KEY_LEN; i++) {
        printf("%02x", key[i]);
    }
    printf("\033[0m\n");

    printf("\033[0;33mexport\033[0m \033[0;35mSFETOOL_IV\033[0m=\033[0;32m");
    for (int i = 0; i < SFETOOL_KEY_LEN; i++) {
        printf("%02x", iv[i]);
    }
    printf("\033[0m\n");
    printf("\n");
    printf("Or, add these lines to your .bashrc or .zshrc file to set them permanently.");
    printf("\n");

}

int isEmailExists(const char *email) {
    size_t usersSize = 0;
    User **users = NULL;
    int loadCode = loadUsers(&users, &usersSize);
    if (loadCode == LOAD_USERS_FILE_OPEN_ERROR) return -1000;
    if (loadCode == LOAD_USERS_MEMORY_ALLOCATION_ERROR) return -1001;
    if (loadCode == LOAD_USERS_DATA_FORMAT_ERROR) return -1002;

    for(size_t i=0; i < usersSize; i++){
        if (strcmp(users[i]->email, email) == 0) {
            cleanupUsers(users, usersSize);
            return 1;
        }
    }
    
    cleanupUsers(users, usersSize);
    return 0;    
}


// Get the informations of a user
User *getUserInfo(const char *email) {
    User **users = NULL;
    size_t usersSize = 0;
    int loadCode = loadUsers(&users, &usersSize);
    if (loadCode == LOAD_USERS_MEMORY_ALLOCATION_ERROR) return NULL;
    if (loadCode == LOAD_USERS_FILE_OPEN_ERROR) return NULL;
    if (loadCode == LOAD_USERS_DATA_FORMAT_ERROR) return NULL;

    User *user = NULL;

    for (size_t index = 0; index < usersSize; index++) {
        if (strcmp(users[index]->email, email) == 0) {
            user = malloc(sizeof(User));

            strncpy(user->id, users[index]->id, USER_ID_MAX * 2 + 1);
            user->id[USER_ID_MAX * 2] = '\0';

            strncpy(user->name, users[index]->name, USER_NAME_MAX);
            user->name[USER_NAME_MAX - 1] = '\0';

            strncpy(user->email, users[index]->email, USER_EMAIL_MAX);
            user->email[USER_EMAIL_MAX - 1] = '\0';

            strncpy(user->password, users[index]->password, USER_PASSWORD_MAX * 2 + 1);
            user->password[USER_PASSWORD_MAX * 2] = '\0';

            user->createdAt = users[index]->createdAt;
            user->updatedAt = users[index]->updatedAt;
        }
    }

    cleanupUsers(users, usersSize);
    return user;
}

// Function to create token `email|timestamp`
unsigned char* createToken(const char* email, size_t* tokenLength) {
    time_t sessionStartAt = time(NULL);
    *tokenLength = USER_EMAIL_MAX + 21;  // Email + "|" + timestamp + null terminator
    unsigned char *token = malloc(*tokenLength);
    if (!token) return NULL;

    snprintf((char*)token, *tokenLength, "%s|%ld", email, sessionStartAt);
    return token;
}

// Function to get the encryption key and IV
int getEncryptionKeyAndIv(unsigned char** key, unsigned char** iv) {
    char* sfetoolKey = getenv("SFETOOL_KEY");
    char* sfetoolIv = getenv("SFETOOL_IV");

    if (!sfetoolKey || !sfetoolIv) {
        return ERR_SFETOOL_KEY_OR_IV_MISSING;
    }

    *key = malloc(16);
    *iv = malloc(16);

    if (!(*key) || !(*iv)) {
        return ERR_KEY_IV_ALLOCATION_FAILED;
    }

    size_t keyByteLen, ivByteLen;
    hexToBytes(sfetoolKey, key, &keyByteLen);
    hexToBytes(sfetoolIv, iv, &ivByteLen);

    return SUCCESS;
}

int createSession(const char *email) {
    FILE *loginFile = fopen(LOGIN_FILE, "wb");
    if (loginFile == NULL) return ERR_FILE_OPEN_FAILED;

    size_t tokenLength;
    unsigned char *token = createToken(email, &tokenLength);
    if (!token) {
        fclose(loginFile);
        return ERR_TOKEN_CREATION_FAILED;
    }

    unsigned char *key = NULL, *iv = NULL;
    int status = getEncryptionKeyAndIv(&key, &iv);
    if (status != SUCCESS) {
        free(token);
        fclose(loginFile);
        return status;
    }

    size_t bufferLength = tokenLength + EVP_CIPHER_block_size(EVP_aes_128_cbc());
    unsigned char *buffer = malloc(bufferLength);
    if (!buffer) {
        free(token);
        free(key);
        free(iv);
        fclose(loginFile);
        return ERR_MEMORY_ALLOCATION_FAILED;
    }

    encrypt(token, tokenLength, buffer, key, iv);

    if (fwrite(buffer, 1, bufferLength, loginFile) < bufferLength) {
        free(buffer);
        free(token);
        free(key);
        free(iv);
        fclose(loginFile);
        return ERR_ENCRYPTION_FAILED;
    }

    free(buffer);
    free(token);
    free(key);
    free(iv);
    fclose(loginFile);
    return SUCCESS;
}

// Function to validate session duration
int validateSession(unsigned char* token) {
    char email[USER_EMAIL_MAX] = {0};
    time_t timeExp = 0;
    sscanf((char*)token, "%[^|]|%ld", email, &timeExp);

    double sessionDuration = difftime(time(NULL), timeExp);

    return (sessionDuration <= 30) ? SUCCESS : ERR_SFETOOL_KEY_OR_IV_MISSING;  // Reusing error code for session timeout
}

// Refactored checkActiveSession function
int checkActiveSession() {
    FILE *loginFile = fopen(LOGIN_FILE, "rb");
    if (loginFile == NULL) return ERR_FILE_OPEN_FAILED;

    unsigned char *key = NULL, *iv = NULL;
    int status = getEncryptionKeyAndIv(&key, &iv);
    if (status != SUCCESS) {
        fclose(loginFile);
        return status;
    }

    size_t bufferLength = USER_EMAIL_MAX + 21 + EVP_CIPHER_block_size(EVP_aes_128_cbc());
    unsigned char *buffer = malloc(bufferLength);
    if (!buffer) {
        free(key);
        free(iv);
        fclose(loginFile);
        return ERR_MEMORY_ALLOCATION_FAILED;
    }

    if (fread(buffer, 1, bufferLength, loginFile) <= 0) {
        free(buffer);
        free(key);
        free(iv);
        fclose(loginFile);
        return ERR_FILE_READ_FAILED;
    }

    unsigned char token[USER_EMAIL_MAX + 21];
    decrypt(buffer, bufferLength, token, key, iv);

    status = validateSession(token);

    free(buffer);
    free(key);
    free(iv);
    fclose(loginFile);

    return status;
}

int computeFileHash(const char *filename, unsigned char *hash_out, unsigned int *hash_len) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        return -1;
    }

    // Create a digest context
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(file);
        return -2;
    }

    // Initialize the SHA-256 digest
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return -3;
    }

    unsigned char buffer[4096];
    size_t bytes_read;

    // Read the file and update the hash
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, bytes_read) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(file);
            return -4;
        }
    }

    fclose(file);

    // Finalize the hash
    if (EVP_DigestFinal_ex(ctx, hash_out, hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -5;
    }

    // Clean up
    EVP_MD_CTX_free(ctx);
    return 0;
}

void printHash(unsigned char *hash, unsigned int hash_length) {
    for (unsigned int i = 0; i < hash_length; ++i) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int appendToCsv(const char *csvFileName, const char *fileName, const char *hash) {
    FILE *file = fopen(csvFileName, "a");
    if (file == NULL) {
        return FILE_OPEN_ERROR;
    }

    if (fprintf(file, "%s,%s\n", fileName, hash) < 0) {
        fclose(file);
        return FILE_WRITE_ERROR;
    }

    fclose(file);
    return SUCCESS;
}

int readFromCsv(const char *csvFileName, const char *fileName, char *hashBuffer, size_t bufferSize) {
    FILE *file = fopen(csvFileName, "r");
    if (file == NULL) {
        return FILE_OPEN_ERROR;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char currentFileName[128], currentHash[128];
        
        // Parse the line
        if (sscanf(line, "%127[^,],%127s", currentFileName, currentHash) == 2) {
            if (strcmp(currentFileName, fileName) == 0) {
                // Copy the hash to the provided buffer
                strncpy(hashBuffer, currentHash, bufferSize - 1);
                hashBuffer[bufferSize - 1] = '\0'; // Ensure null termination
                fclose(file);
                return SUCCESS;
            }
        }
    }

    fclose(file);
    return FILENAME_NOT_FOUND;
}