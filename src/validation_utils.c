#include <stdarg.h>
#include <stdbool.h>
#include <ctype.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include "validation_utils.h"



ValidationResult minLength(char *input, void *param) {
    if (input == NULL) return NULL_INPUT; // Memory Safety with strlen
    int minLength = *(int *)param;
    if (strlen(input) >= minLength) return VALID;
    return TOO_SHORT;
}

ValidationResult maxLength(char *input, void *param) {
    if (input == NULL) return NULL_INPUT;
    int maxLength = *(int *)param;
    if (strlen(input) <= maxLength) return VALID;
    return TOO_LONG;
}

ValidationResult isDigit(char *input, void *param) {
    if (input == NULL) return NULL_INPUT;
    (void)param; // Unused variable
    for (int i = 0; input[i] != '\0'; i++) {
        if (!isdigit((unsigned char)input[i])) {
            return NON_DIGIT_FOUND;
        }
    }
    return VALID;
}

ValidationResult isAlpha(char *input, void *param) {
    if (input == NULL) return NULL_INPUT;
    (void)param; // Unused variable
    for (int i = 0; input[i] != '\0'; i++) {
        if (!isalpha((unsigned char)input[i])) {
            return NON_ALPHA_FOUND;
        }
    }
    return VALID;
}

ValidationResult isEmail(char *input, void *param) {
    if (input == NULL) return NULL_INPUT;
    (void)param;  // Unused parameter
    const char *pattern = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
    regex_t regex;
    int result;

    // Compile the regular expression
    result = regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB);
    if (result != 0) {
        // If compilation fails, return specific error
        return REGEX_COMPILATION_FAILED;
    }

    // Execute the regex match
    result = regexec(&regex, input, 0, NULL, 0);

    // Free the regex memory
    regfree(&regex);

    // Return EMAIL_FORMAT_INVALID if no match, otherwise VALID
    return (result == 0) ? VALID : EMAIL_FORMAT_INVALID;
}

ValidationResult isPassword(char *input, void *param) {
    if (input == NULL) return NULL_INPUT;
    (void)param;  // Unused parameter
    int length = strlen(input);
    bool hasUpper = false;
    bool hasLower = false;
    bool hasDigit = false;
    bool hasSpecial = false;

    // Iterate through each character to check for required criteria
    for (int i = 0; i < length; i++) {
        if (isupper((unsigned char)input[i])) {
            hasUpper = true;
        } else if (islower((unsigned char)input[i])) {
            hasLower = true;
        } else if (isdigit((unsigned char)input[i])) {
            hasDigit = true;
        } else if (ispunct((unsigned char)input[i])) {
            hasSpecial = true;
        }
    }

    
    if (!hasUpper) return MISSING_UPPERCASE;
    if (!hasLower) return MISSING_LOWERCASE;
    if (!hasDigit) return MISSING_DIGIT;
    if (!hasSpecial) return MISSING_SPECIAL;

    // Return true if all conditions are met, false otherwise
    return VALID;
}

ValidationResult isAlphaNumeric(char *input, void *param) {
    if (input == NULL) return NULL_INPUT;
    (void)param; // Unused variable
    for (int i = 0; input[i] != '\0'; i++) {
        if (!isalpha((unsigned char)input[i]) && !isdigit((unsigned char)input[i])) {
            return NON_ALPHANUMERIC_FOUND;
        }
    }
    return VALID;
}

ValidationResult validate(char *input, ValidationRule rules[], int ruleCount) {
    for (int i = 0; i < ruleCount; i++) {
        ValidationResult result = rules[i].func(input, rules[i].param);
        
        if (result != VALID) {
            return result; // Return the specific failure code
        }
    }
    return VALID; // All rules passed
}