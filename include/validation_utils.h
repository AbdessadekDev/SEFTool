#ifndef VALIDATION_UTILS_H
#define VALIDATION_UTILS_H

/**
 * @enum ValidationResult
 * @brief Represents various outcomes of an input validation check.
 * 
 * Each value corresponds to a specific validation result:
 * - `VALID`: Input meets validation criteria.
 * - `TOO_SHORT`: Input length is less than the required minimum.
 * - `TOO_LONG`: Input length exceeds the allowed maximum.
 * - `MISSING_UPPERCASE`: Input lacks an uppercase letter (for passwords).
 * - `MISSING_LOWERCASE`: Input lacks a lowercase letter (for passwords).
 * - `MISSING_DIGIT`: Input lacks a numeric character (for passwords).
 * - `MISSING_SPECIAL`: Input lacks a special character (for passwords).
 * - `NON_DIGIT_FOUND`: Input contains non-numeric characters.
 * - `NON_ALPHA_FOUND`: Input contains non-alphabetic characters.
 * - `REGEX_COMPILATION_FAILED`: An error occurred while compiling a regular expression.
 * - `EMAIL_FORMAT_INVALID`: Input does not match expected email format.
 * - `NULL_INPUT`: Input is NULL.
 */
typedef enum {
    VALID,
    TOO_SHORT,
    TOO_LONG,
    NULL_INPUT,
    MISSING_UPPERCASE,
    MISSING_LOWERCASE,
    MISSING_DIGIT,
    MISSING_SPECIAL,
    NON_DIGIT_FOUND,
    NON_ALPHA_FOUND,
    REGEX_COMPILATION_FAILED,
    EMAIL_FORMAT_INVALID,
} ValidationResult;

/**
 * @typedef ValidationFunc
 * @brief Defines the function pointer type for validation functions.
 * 
 * @param input The string to be validated.
 * @param param Additional parameter for validation (e.g., min or max length).
 * @return ValidationResult representing the outcome of the validation.
 */
typedef ValidationResult (*ValidationFunc)(char *input, void *param);

/**
 * @struct ValidationRule
 * @brief Represents a validation rule for an input.
 * 
 * This struct combines a validation function, a parameter for that function,
 * and a failure code to return if validation fails.
 * 
 * Fields:
 * - `func`: A pointer to the validation function.
 * - `param`: Parameter for the validation function (e.g., minimum length).
 * - `failCode`: Code to return if validation fails for this rule.
 */
typedef struct {
    ValidationFunc func;   // The validation function
    void *param;           // Parameter for the rule, e.g., min length, max length
    ValidationResult failCode; // Code to return on failure
} ValidationRule;

//--------------------------Validation functions-----------------------
/**
 * @brief Validates that the input length is at least the specified minimum.
 * 
 * @param input The string to validate.
 * @param param Pointer to an integer representing the minimum length.
 * @return `VALID` if input meets minimum length; `TOO_SHORT` or `NULL_INPUT` otherwise.
 */
ValidationResult minLength(char *input, void *param);

/**
 * @brief Validates that the input length does not exceed the specified maximum.
 * 
 * @param input The string to validate.
 * @param param Pointer to an integer representing the maximum length.
 * @return `VALID` if input meets maximum length; `TOO_LONG` or `NULL_INPUT` otherwise.
 */
ValidationResult maxLength(char *input, void *param);

/**
 * @brief Validates that the input contains only digit characters.
 * 
 * @param input The string to validate.
 * @param param Unused; pass NULL.
 * @return `VALID` if input contains only digits; `NON_DIGIT_FOUND` or `NULL_INPUT` otherwise.
 */

ValidationResult isDigit(char *input, void *param);

/**
 * @brief Validates that the input contains only alphabetic characters.
 * 
 * @param input The string to validate.
 * @param param Unused; pass NULL.
 * @return `VALID` if input contains only alphabetic characters; `NON_ALPHA_FOUND` or `NULL_INPUT` otherwise.
 */
ValidationResult isAlpha(char *input, void *param);

/**
 * @brief Validates that the input follows a standard email format.
 * 
 * Uses regular expressions to validate email structure.
 * 
 * @param input The string to validate.
 * @param param Unused; pass NULL.
 * @return `VALID` if input matches email format; `EMAIL_FORMAT_INVALID`, `REGEX_COMPILATION_FAILED`, or `NULL_INPUT` otherwise.
 */
ValidationResult isEmail(char *input, void *param);

/**
 * @brief Validates that the input meets password requirements.
 * 
 * Requirements include:
 * - Contains at least one uppercase letter.
 * - Contains at least one lowercase letter.
 * - Contains at least one digit.
 * - Contains at least one special character.
 * 
 * @param input The string to validate.
 * @param param Unused; pass NULL.
 * @return `VALID` if all password criteria are met; specific code (e.g., `MISSING_UPPERCASE`) or `NULL_INPUT` otherwise.
 */
ValidationResult isPassword(char *input, void *param);

/**
 * @brief Validates input based on an array of validation rules.
 * 
 * Iterates over the provided rules and applies each validation function
 * to the input. Returns the first encountered failure code, or `VALID`
 * if all rules pass.
 * 
 * @param input The string to validate.
 * @param rules Array of `ValidationRule` specifying the rules to apply.
 * @param ruleCount The number of rules in the `rules` array.
 * @return `VALID` if all rules pass; the first failure code encountered otherwise.
 */
ValidationResult validate(char *input, ValidationRule rules[], int ruleCount);



#endif