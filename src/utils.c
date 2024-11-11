// standards
#include <stdio.h>
#include <string.h>

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