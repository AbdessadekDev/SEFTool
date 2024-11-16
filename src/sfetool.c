#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
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
    if (remove(filename) != 0) return ENCRYPTFILE_FILE_REPLACEMENT_ERROR;

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

    return DECRYPTFILE_SUCCESS;
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

int isDuplicatedEmail(const char *email) {
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