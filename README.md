## Secure File Encryption Tool

> A simple file-based encryption tool. This tool will allow users to encrypt and decrypt files securely using encryption algorithms

### Features:
+ **User Login System**:
    Users must authenticate themselves before using the tool.
    Passwords will be hashed and stored securely.

+ **File Encryption**:
    Users can select any file to encrypt using AES (Advanced Encryption Standard) from the OpenSSL library.
    The encryption key will be generated based on the user’s password.
    Encrypted files will have a .enc extension.

+ **File Decryption**:
    Users can decrypt files they previously encrypted.
    The tool will ask for the correct password, and if provided, the file will be restored to its original state.

+ **File Integrity Check**:
    Verify the integrity of the decrypted file by checking if it matches the original file’s hash (computed before encryption).

+ **User Management**:
    New users can register with the system.
    users can change their password, which re-encrypts their existing encrypted files with the new key.

+ **Logging**:
    All actions (login, encryption, decryption) with timestamps to a file for auditing purposes.

