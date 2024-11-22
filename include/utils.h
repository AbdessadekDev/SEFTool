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
 * @brief Add a log message to a given file log, at the current time.
 * 
 * @param level Just like a string alert or like the type of the message, (e.g. INFO, WORNING...)
 * @param message the message of log.
 * @param fileName the name the log file.
 * @param file the name of the file where call this function. (e.g. __FILE__).
 * @param function the name of the function where this function is called.
 */
int addLog(const char *level, const char *message, const char *fileName, const char *file, const char *function);

void handleLoginUser(int result);
void handleRegisterResult(int result);
void disableEcho();
void enableEcho();

#endif /* UTILS_H */