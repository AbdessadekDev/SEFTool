// standard headers
#include <stdio.h>
#include <stdlib.h>
#include <uuid/uuid.h>
#include <time.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>


#include "auth.h"
#include "sfetool.h"
#include "utils.h"

int loadUsers(User **users, size_t *usersSize) {
    char buffer[USER_INFO_MAX];

    FILE *pUsersFile = fopen(USERS_FILE, "r");
    if (pUsersFile == NULL) return LOAD_USERS_FILE_OPEN_ERROR;

    // Count lines to determine number of users
    size_t count = 0;
    while (fgets(buffer, USER_INFO_MAX, pUsersFile)) {
        count++;
    }
    fseek(pUsersFile, 0, SEEK_SET);

    *users = malloc(count * sizeof(User));
    if (*users == NULL) {
        fclose(pUsersFile);
        return LOAD_USERS_MEMORY_ALLOCATION_ERROR;
    }
    *usersSize = count;

    // Read each user record
    size_t index = 0;
    while (fgets(buffer, USER_INFO_MAX, pUsersFile) && index < *usersSize) {
        char userId[USER_ID_MAX];
        char name[USER_NAME_MAX];
        char email[USER_EMAIL_MAX];
        char password[USER_PASSWORD_MAX];
        time_t createdAt;
        time_t updatedAt;

        // Read each field,
        int matched = sscanf(buffer, "%s|%s|%s|%s|%ld|%ld\n", userId, name, email, password, &createdAt, &updatedAt);
        if (matched != 6) {
            fclose(pUsersFile);
            free(*users);
            return LOAD_USERS_DATA_FORMAT_ERROR;
        }

        // Copy fields
        strncpy((*users)[index].id, userId, USER_ID_MAX);
        (*users)[index].id[USER_ID_MAX - 1] = '\0';

        strncpy((*users)[index].name, name, USER_NAME_MAX);
        (*users)[index].name[USER_NAME_MAX - 1] = '\0';

        strncpy((*users)[index].email, email, USER_EMAIL_MAX);
        (*users)[index].email[USER_EMAIL_MAX - 1] = '\0';

        strncpy((*users)[index].password, password, USER_PASSWORD_MAX);
        (*users)[index].password[USER_PASSWORD_MAX - 1] = '\0';

        (*users)[index].createdAt = createdAt;
        (*users)[index].updatedAt = updatedAt;

        index++;
    }

    fclose(pUsersFile);
    return LOAD_USERS_SUCCESS;
}

int saveUser(User *user) {
    if (!isFileExists(USERS_FILE)) {
        if (mkdir("data",0777) == - 1) return SAVE_USERS_FILE_OPEN_ERROR;
    }
    FILE *pUserFile = fopen(USERS_FILE, "a");
    if (pUserFile == NULL) return SAVE_USERS_FILE_OPEN_ERROR;
    if (fprintf(pUserFile,"%s|%s|%s|%s|%ld|%ld\n",user->id,user->name,user->email,user->password,user->createdAt,user->updatedAt) < 6) {
        fclose(pUserFile);
        return SAVE_USERS_UNABLE_TO_WRITE;
    }
    fclose(pUserFile);
    return SAVE_USERS_SUCCESS;
}

int encryptFile(const char *filename, unsigned char *key, unsigned char *iv) {
    FILE *file = fopen(filename, "r+");
    if (file == NULL) return ENCRYPTFILE_UNABLE_TO_OPEN_FILE;

    // Initialize encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(file);
        return ENCRYPTFILE_FIALS_TO_INI_CTX;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        return ENCRYPTFILE_FIALS_TO_INI_ENC;
    }

    unsigned char buffer[USER_INFO_MAX];
    int encryptedLinesLen = countLines(filename);
    if (encryptedLinesLen <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        return ENCRYPTFILE_UNABLE_TO_OPEN_FILE_COUNT;
    }

    unsigned char **encryptedLines = malloc(encryptedLinesLen * sizeof(unsigned char*));
    int *encryptedLengths = malloc(encryptedLinesLen * sizeof(int)); // Track each encrypted line's length
    if (encryptedLines == NULL || encryptedLengths == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        free(encryptedLines);
        free(encryptedLengths);
        return ENCRYPTFILE_MEMORY_ALLOCATION_ERR;
    }

    int index = 0;
    while (fgets((char*)buffer, USER_INFO_MAX, file)) {
        int outlen1, outlen2;
        encryptedLines[index] = malloc(USER_INFO_MAX + EVP_CIPHER_block_size(EVP_aes_128_cbc()));
        if (encryptedLines[index] == NULL) {
            for (int i = 0; i < index; i++) free(encryptedLines[i]);
            free(encryptedLines);
            free(encryptedLengths);
            EVP_CIPHER_CTX_free(ctx);
            fclose(file);
            return ENCRYPTFILE_MEMORY_ALLOCATION_ERR;
        }

        // Encrypt the current line
        if (1 != EVP_EncryptUpdate(ctx, encryptedLines[index], &outlen1, buffer, strlen((char*)buffer))) {
            for (int i = 0; i <= index; i++) free(encryptedLines[i]);
            free(encryptedLines);
            free(encryptedLengths);
            EVP_CIPHER_CTX_free(ctx);
            fclose(file);
            return ENCRYPTFILE_ENCRYPTION_ERR;
        }

        if (1 != EVP_EncryptFinal_ex(ctx, encryptedLines[index] + outlen1, &outlen2)) {
            for (int i = 0; i <= index; i++) free(encryptedLines[i]);
            free(encryptedLines);
            free(encryptedLengths);
            EVP_CIPHER_CTX_free(ctx);
            fclose(file);
            return ENCRYPTFILE_ENCRYPTION_ERR;
        }

        encryptedLengths[index] = outlen1 + outlen2; // Store encrypted length
        index++;
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(file);

    // Write encrypted lines to a new file
    int fileNameEncLen = snprintf(NULL, 0, "%s.enc", filename) + 1;
    char *fileNameEnc = malloc(fileNameEncLen);
    snprintf(fileNameEnc, fileNameEncLen, "%s.enc", filename);

    if (writeLines(fileNameEnc, encryptedLines, encryptedLengths, encryptedLinesLen) != 0) {
        for (int i = 0; i < encryptedLinesLen; i++) free(encryptedLines[i]);
        free(encryptedLines);
        free(encryptedLengths);
        free(fileNameEnc);
        return ENCRYPTFILE_ENCRYPTION_ERR;
    }
    if (remove(filename) != 0) return ENCRYPTFILE_UNABLE_TO_REMOVE_ACTUAL_FILE;

    for (int i = 0; i < encryptedLinesLen; i++) free(encryptedLines[i]);
    free(encryptedLines);
    free(encryptedLengths);
    free(fileNameEnc);
    return ENCRYPTFILE_SUCCESS;
}

int decryptFile(const char *encryptedFileName,unsigned char *key, unsigned char *iv) {
    FILE *file = fopen(encryptedFileName, "rb");
    if (file == NULL) return DECRYPTFILE_UNABLE_TO_OPEN_FILE;
    
    int len = strlen(encryptedFileName) - 4;
    char *outputFileName = malloc(len);
    removeEncExtension(encryptedFileName, outputFileName);

    FILE *outputFile = fopen(outputFileName, "w");
    if (outputFile == NULL) {
        fclose(file);
        return DECRYPTFILE_UNABLE_TO_OPEN_OUTPUT;
    }

    // Initialize decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(file);
        fclose(outputFile);
        return DECRYPTFILE_FAIL_TO_INIT_CTX;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        fclose(outputFile);
        return DECRYPTFILE_FAIL_TO_INIT_DEC;
    }

    // Buffer to hold each encrypted line and its decrypted form
    unsigned char encryptedBuffer[USER_INFO_MAX + EVP_CIPHER_block_size(EVP_aes_128_cbc())];
    unsigned char decryptedBuffer[USER_INFO_MAX];
    int decryptedLen = 0, finalLen = 0;

    while (!feof(file)) {
        // Read a line of encrypted data
        size_t encryptedSize = fread(encryptedBuffer, 1, sizeof(encryptedBuffer), file);
        if (encryptedSize <= 0) break;

        // Decrypt the current line
        if (1 != EVP_DecryptUpdate(ctx, decryptedBuffer, &decryptedLen, encryptedBuffer, encryptedSize)) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(file);
            fclose(outputFile);
            return DECRYPTFILE_DECRYPTION_ERR;
        }

        // Write decrypted data to output file
        fwrite(decryptedBuffer, 1, decryptedLen, outputFile);
    }

    // Finalize decryption to handle padding
    if (1 != EVP_DecryptFinal_ex(ctx, decryptedBuffer, &finalLen)) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        fclose(outputFile);
        return DECRYPTFILE_DECRYPTION_ERR;
    }

    // Write any remaining decrypted data to output file
    fwrite(decryptedBuffer, 1, finalLen, outputFile);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    fclose(file);
    fclose(outputFile);
    return DECRYPTFILE_SUCCESS;
}

void genKey(char *name) {
    unsigned char key[SFETOOL_KEY_LEN];
    char hex[SFETOOL_KEY_LEN * 2 + 1];
    RAND_bytes(key, SFETOOL_KEY_LEN);
    byteToHex(key, SFETOOL_KEY_LEN, hex);

    printf("Generated key for %s:\n", name);
    printf("Set the following as an environment variable in your system:\n\n");
    printf("    export SFETOOL_%s=%s\n\n", name, hex);
    // printf("Instructions:\n");
    // printf("  - For Linux/macOS, run the above command in your terminal.\n");
    // printf("  - For Windows, use 'setx SFETOOL_%s \"%s\"' in Command Prompt.\n", name, hex);
    printf("Note: Restart your terminal or command prompt to ensure the variable is available.\n");
}