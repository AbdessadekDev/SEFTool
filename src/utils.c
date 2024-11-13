// standards
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

// openssl
#include <openssl/evp.h>
#include <openssl/rand.h>

// custom
#include "utils.h"


int hashPassword(unsigned char *password, unsigned char *hashedPassword) {
    EVP_MD_CTX *mdCtx;
    unsigned int hashLen;

    // Initialize the digest context
    if (!(mdCtx = EVP_MD_CTX_new())) return -1;

    // Initialize the SHA-256 hashing algorithm
    if (1 != EVP_DigestInit_ex(mdCtx, EVP_sha256(), NULL)) return -2;

    // Feed the password data into the hashing function
    if (1 != EVP_DigestUpdate(mdCtx, password, strlen((char*)password))) return -3;

    // Retrieve the final hashed result
    if (1 != EVP_DigestFinal_ex(mdCtx, hashedPassword, &hashLen)) return -4;

    // Free the digest context to avoid memory leaks
    EVP_MD_CTX_free(mdCtx);
    return (int)hashLen;
}


void byteToHex(unsigned char* bytes, int bytesLen, char *hex) {
    for (int i = 0; i < bytesLen; i++) 
        sprintf(&hex[i * 2], "%02x", bytes[i]);  // Convert each byte to two hexadecimal characters
    hex[bytesLen * 2] = '\0';  // Null-terminate the resulting string
}


void hexToBytes(const char *hex, unsigned char **bytes, size_t *length) {
    size_t len = strlen(hex);
    *length = len / 2;
    *bytes = (unsigned char *)malloc(*length);  // Allocate memory for the byte array

    for (size_t i = 0; i < *length; i++) {
        sscanf(hex + (i * 2), "%2hhx", &(*bytes)[i]);  // Convert each pair of hex characters to a byte
    }
}

bool isFileExists(char *fileName) {
    FILE *file = fopen(fileName, "r");
    if (file == NULL) {
        if (errno == 2) return false;
        return true;
    }
    fclose(file);
    return true;
}

int countLines(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) return -1;
    int count = 0;
    char buffer[300];
    while(fgets(buffer, 300, file)) count++;
    fclose(file);
    return count;
}

int writeLines(const char *fileName, unsigned char **lines, int *lineLengths, int linesSize) {
    FILE *file = fopen(fileName, "wb");
    if (file == NULL) return -33;

    for (int index = 0; index < linesSize; index++) {
        if (fwrite(lines[index], 1, lineLengths[index], file) != lineLengths[index]) {
            fclose(file);
            return -34;
        }
    }
    fclose(file);
    return 0;
}


void removeEncExtension(const char *fileName, char *outputFile) {
    // Copy the original file name to outputFile
    strcpy(outputFile, fileName);

    // Find the last occurrence of ".enc" in outputFile
    char *extension = strstr(outputFile, ".enc");

    // If ".enc" is found at the end, replace it with a null terminator
    if (extension && strcmp(extension, ".enc") == 0) {
        *extension = '\0'; // Remove the ".enc" extension
    }
}