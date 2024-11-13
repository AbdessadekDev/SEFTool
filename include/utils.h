#include <stdbool.h>
#ifndef UTILS_H
#define UTILS_H

/**
 * Hashes a password using SHA-256.
 * 
 * @param password       The password to hash (input).
 * @param hashedPassword Buffer to store the resulting hashed password (output).
 * @return               The length of the hashed password on success, or a negative error code on failure.
 */
int hashPassword(unsigned char *password, unsigned char *hashedPassword);

/**
 * Converts an array of bytes to a hexadecimal string.
 * 
 * @param bytes    The byte array to convert.
 * @param bytesLen The length of the byte array.
 * @param hex      Buffer to store the resulting hexadecimal string. Must be large enough to hold 2 * bytesLen + 1.
 */
void byteToHex(unsigned char* bytes, int bytesLen, char *hex);

/**
 * Converts a hexadecimal string to an array of bytes.
 * 
 * @param hex     The hexadecimal string to convert.
 * @param bytes   Pointer to an allocated array of bytes (output).
 * @param length  Pointer to store the length of the resulting byte array.
 */
void hexToBytes(const char *hex, unsigned char **bytes, size_t *length);

/**
 * @brief Checks if a file exists at the specified path.
 *
 * @param fileName The name of the file to check.
 * @return true if the file exists, false if it does not exist or if an error occurs.
 */
bool isFileExists(char *fileName);

/**
 * @brief Counts the number of lines in a file.
 *
 * @param filename The name of the file to count lines in.
 * @return The number of lines in the file, or -1 if the file cannot be opened.
 */
int countLines(const char *filename);

/**
 * @brief Writes an array of encrypted lines to a binary file.
 *
 * @param fileName The name of the file to write to.
 * @param lines A 2D array of encrypted lines to be written to the file.
 * @param lineLengths An array containing the length of each line in `lines`.
 * @param linesSize The number of lines to write.
 * @return 0 if writing is successful, or an error code (-33 if the file cannot be opened, 
 *         -34 if there is a write error).
 */
int writeLines(const char *fileName, unsigned char **lines, int *lineLengths, int linesSize);


/**
 * @brief Removes the ".enc" extension from a filename.
 *
 * @param fileName The original file name with the ".enc" extension.
 * @param outputFile The output buffer to store the filename without the ".enc" extension.
 */
void removeEncExtension(const char *fileName, char *outputFile);


#endif /* UTILS_H */