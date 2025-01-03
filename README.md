# Encryption-Decryption-Tool

This Python program allows users to securely encrypt and decrypt plaintext messages and files. It leverages the cryptography library to implement a hybrid encryption system that uses a Key Encryption Key (KEK) and a Data Encryption Key (DEK) for enhanced security. Encrypted data is stored in JSON format for easy access and retrieval.

Features

1. Encrypt Plaintext:

Encrypt user-inputted plaintext messages using a randomly generated DEK.
Secure the DEK using a KEK derived from a user-provided password.
Store the encrypted data and metadata in JSON format.

2. Decrypt Plaintext:

Decrypt encrypted plaintext files by re-deriving the KEK and DEK.
Validate user-provided passwords to ensure secure decryption.

3. Encrypt Files:

Encrypt any file type (e.g., .txt, .pdf, .docx, images).
Store the encrypted file content, metadata, and original file name securely in JSON format.

4. Decrypt Files:

Decrypt encrypted files and save them with their original file names prefixed with decrypted.
Supports renamed or relocated encrypted files.

5. Menu-Based Interface:

Provides an interactive menu for users to:

i)Encrypt plaintext

ii) Decrypt plaintext

iii) Encrypt a file

iv) Decrypt a file

v) Exit the program

How It Works

Hybrid Encryption:

A Key Encryption Key (KEK) is derived from a user-provided password using a key derivation function (PBKDF2).
A Data Encryption Key (DEK) is randomly generated and used to encrypt the actual data (plaintext or file).
The DEK is encrypted using the KEK, ensuring that the DEK is protected.
JSON Storage:

Encrypted data is stored in JSON format along with:

1. The salt for KEK derivation.
2. The encrypted DEK.
3. The encrypted data or file content.
4. (For files) The original file name.

Decryption Process:

The user provides the path to the encrypted file and their password.
The KEK is re-derived using the stored salt and user password.
The DEK is decrypted using the KEK, and the actual data is decrypted using the DEK.

Usage

Running the Program

Clone the repository:

git clone https://github.com/JelaniAHoward/Encryption-Decryption-Tool

Install the required Python libraries:

pip install cryptography

Run the program:

python Index.py

Menu Options

Option 1: Encrypt Plaintext

Enter a password and a plaintext message.
The encrypted message will be stored in encrypted_text.txt.

Option 2: Decrypt Plaintext

Enter the password used during encryption and the path to the encrypted file.
The decrypted message will be displayed and stored in decrypted_text.

Option 3: Encrypt a File

Enter a password and the path to the file you want to encrypt.
The encrypted file will be stored in encryptedfile.enc.

Option 4: Decrypt a File

Enter the password used during encryption and the path to the encrypted file.
The decrypted file will be saved with its original name prefixed with decrypted.

Option 5: Exit

Exit the program.

Error Handling

Invalid Password:

If an incorrect password is provided during decryption, the program displays an error and terminates the operation.

File Not Found:

If the user provides an incorrect file path, the program displays a "File not found" error.

Corrupted Data:

If the encrypted file is corrupted or tampered with, decryption will fail gracefully with an error message.

Input Validation:

Ensures the user provides valid choices for menu options and file paths.

Dependencies

Python 3.x

cryptography library

Install using: 
pip install cryptography

Security Notes

1. Passwords are not stored anywhere in plaintext. They are used only for deriving the KEK.

2. The program uses a randomly generated salt for each encryption, ensuring that the same password produces different KEKs for different encryptions.

3. Encrypted data is stored securely in JSON format, but users should protect the JSON files to prevent unauthorized access.

License

  This project is licensed under the MIT License. See the LICENSE file for more details.

Acknowledgments

  Built using the cryptography library.

  Inspired by best practices in cryptographic security.
