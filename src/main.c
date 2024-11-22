#include "stdio.h"
#include "stdlib.h"
#include "sfetool.h"
#include <openssl/rand.h>
#include <string.h>
#include <termio.h>

#include "auth.h"
#include "utils.h"

int main(int argc, char **args)
{
    
    if (strcmp(args[1], "--init-keys") == 0){
        setupKeys();
        return 0;
    }

    if (strcmp(args[1], "--login") == 0) {
        int isActive = checkActiveSession();
        if (isActive == SUCCESS || isActive == -100) {
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
        return 0;
    }

    if (strcmp(args[1], "--register") == 0) {
        char name[USER_NAME_MAX];
        char password[USER_PASSWORD_MAX];
        char confirmPassword[USER_PASSWORD_MAX];
        char email[USER_EMAIL_MAX];

        strncpy(email, args[2], USER_EMAIL_MAX);
        email[USER_EMAIL_MAX - 1] = '\0';

        printf("\033[0;34mRegister:\033[0m\n");
        printf("Name: ");
        fgets(name, USER_NAME_MAX, stdin);
        printf("Password: ");
        disableEcho();
        fgets(password, USER_PASSWORD_MAX, stdin);
        enableEcho();
        printf("\n");
        printf("Confirm Password: ");
        disableEcho();
        fgets(confirmPassword, USER_PASSWORD_MAX, stdin);
        enableEcho();
        printf("\n");
        name[strcspn(name, "\n")] = '\0';
        password[strcspn(password, "\n")] = '\0';
        confirmPassword[strcspn(confirmPassword, "\n")] = '\0';
        int registerResult = registerUser(name, email, password, confirmPassword);
        handleRegisterResult(registerResult);
    }
    return 0;
}