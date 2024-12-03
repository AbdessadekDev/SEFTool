#include "stdio.h"
#include "stdlib.h"
#include "sfetool.h"
#include <openssl/rand.h>
#include <string.h>
#include <termio.h>

#include "auth.h"
#include "utils.h"
#include "validation_utils.h"

void printHelp() {
    printf("Usage: sfetool [OPTION] [ARGS]\n");
    printf("\nOptions:\n");
    printf("  --init-keys               Initialize encryption keys.\n");
    printf("  --login [email]           Login with the specified email.\n");
    printf("  --register [email]        Register a new account with the specified email.\n");
    printf("  --help                    Display this help message.\n");
}

int main(int argc, char **args) {
    if (argc < 2) {
        printf("Error: Missing arguments.\n");
        printHelp();
        return EXIT_FAILURE;
    }

    if (strcmp(args[1], "--help") == 0) {
        printHelp();
        return EXIT_SUCCESS;
    }

    if (strcmp(args[1], "--init-keys") == 0) {
        setupKeys();

    }

    if (strcmp(args[1], "--login") == 0) {
        if (argc < 3) {
            printf("Error: Missing email argument for login.\n");
            return EXIT_FAILURE;
        }

        int isActive = checkActiveSession();
        if (isActive == -12) {
            printf("Run: sfetool --init-keys\nAnd try again.\n");
            return EXIT_FAILURE;
        }

        if (isActive == SUCCESS || isActive == -100 || isActive == -105) {
            printf("\033[0;34mLogin:\033[0m\n");
            char email[USER_EMAIL_MAX];
            char password[USER_PASSWORD_MAX];

            strncpy(email, args[2], USER_EMAIL_MAX);
            email[USER_EMAIL_MAX - 1] = '\0';

            printf("Please enter your password: ");
            disableEcho();
            fgets(password, USER_PASSWORD_MAX, stdin);
            enableEcho();
            password[strcspn(password, "\n")] = '\0';

            int loginResult = loginUser(email, password);
            handleLoginUser(loginResult);
        }
        return EXIT_SUCCESS;
    }

    if (strcmp(args[1], "--register") == 0) {
        if (argc < 3) {
            printf("Error: Missing email argument for registration.\n");
            return EXIT_FAILURE;
        }

        char name[USER_NAME_MAX];
        char password[USER_PASSWORD_MAX];
        char confirmPassword[USER_PASSWORD_MAX];
        char email[USER_EMAIL_MAX];

        strncpy(email, args[2], USER_EMAIL_MAX);
        email[USER_EMAIL_MAX - 1] = '\0';

        printf("\033[0;34mRegister:\033[0m\n");
        printf("Name: ");
        fgets(name, USER_NAME_MAX, stdin);
        name[strcspn(name, "\n")] = '\0';

        printf("Password: ");
        disableEcho();
        fgets(password, USER_PASSWORD_MAX, stdin);
        enableEcho();
        password[strcspn(password, "\n")] = '\0';

        printf("\nConfirm Password: ");
        disableEcho();
        fgets(confirmPassword, USER_PASSWORD_MAX, stdin);
        enableEcho();
        confirmPassword[strcspn(confirmPassword, "\n")] = '\0';

        if (strcmp(password, confirmPassword) != 0) {
            printf("\nError: Passwords do not match.\n");
            return EXIT_FAILURE;
        }

        int registerResult = registerUser(name, email, password, confirmPassword);
        handleRegisterResult(registerResult);
        return EXIT_SUCCESS;
    }

    printf("Error: Unknown option '%s'.\n", args[1]);
    printHelp();
    return EXIT_FAILURE;
}
