#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "sfetool.h"

// Load user data from file and populate the users array
int loadUsers(User **users, size_t *usersSize) {
    FILE *file = fopen(USERS_FILE, "rb");
    if (!file) return LOAD_USERS_FILE_OPEN_ERROR;

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    rewind(file);

    if (fileSize % sizeof(User) != 0) {
        fclose(file);
        return LOAD_USERS_DATA_FORMAT_ERROR;
    }

    *usersSize = fileSize / sizeof(User);
    *users = malloc(fileSize);
    if (!*users) {
        fclose(file);
        return LOAD_USERS_MEMORY_ALLOCATION_ERROR;
    }

    fread(*users, sizeof(User), *usersSize, file);
    fclose(file);
    return LOAD_USERS_SUCCESS;
}

// Append a single user to the users file
int saveUser(User *user) {
    FILE *file = fopen(USERS_FILE, "ab");
    if (!file) return SAVE_USERS_FILE_OPEN_ERROR;

    if (fwrite(user, sizeof(User), 1, file) != 1) {
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
