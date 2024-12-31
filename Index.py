import base64
import json
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken


#Creating Key Encryption Key using a key derivation function
def create_kek(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key_encryption_key = base64.urlsafe_b64encode(kdf.derive(password))
    f_kek = Fernet(key_encryption_key)
    return f_kek, salt

#Creating Data Encryption Key
def create_dek():
    data_encryption_key = Fernet.generate_key()
    f_dek = Fernet(data_encryption_key)
    return f_dek, data_encryption_key

#Using the Key Encryption Key
def use_kek(confirm_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key_encryption_key = base64.urlsafe_b64encode(kdf.derive(confirm_password))
    f_kek = Fernet(key_encryption_key)
    return f_kek

#Encrypting Inputted Plaintext
def enc_text():
    password = input("Enter password: ").encode('utf-8')
    f_kek, salt = create_kek(password)
    f_dek, data_encryption_key = create_dek()
    encrypted_dek = f_kek.encrypt(data_encryption_key)
    plain_text_message = input("Enter your plaintext message: ").encode('utf-8')

    try:
        encrypted_text = f_dek.encrypt(plain_text_message)
        decoded_encrypted_text = encrypted_text.decode()
        print(decoded_encrypted_text)

        #Storing the needed data for decryption in JSON format
        stored_data = {
            "salt": base64.urlsafe_b64encode(salt).decode(),
            "encrypted dek": encrypted_dek.decode(),
            "encrypted text": decoded_encrypted_text
        }

        with open('encrypted_text.txt', 'w') as key_file:
            json.dump(stored_data, key_file, indent=4)

    except Exception as e:
        print("Error during encryption:", e)



#Decrypting Inputted Plaintext
def dec_text():
    try:
        confirm_password = input("Re-Enter password used to encrypt plaintext: ").encode('utf-8')
        try:

            encrypted_file_path = input("Enter path to the encrypted file: ")

            with open(encrypted_file_path, 'r') as key_file:
                stored_data = json.load(key_file)
                salt = base64.urlsafe_b64decode(stored_data["salt"])
                encrypted_dek = stored_data["encrypted dek"]
                cipher_text_message = stored_data["encrypted text"]

            f_kek = use_kek(confirm_password, salt)
            decrypted_dek = f_kek.decrypt(encrypted_dek)
            f_dek = Fernet(decrypted_dek)
            decrypted_text = f_dek.decrypt(cipher_text_message).decode()
            print(decrypted_text)

            with open('decrypted_text', 'w') as key_file2:
                try:
                    key_file2.write(decrypted_text)
                except InvalidToken:
                    print("Error: Invalid ciphertext or decryption key.")
                except Exception as e:
                    print("Error during decryption:", e)
        except FileNotFoundError:
            print("File not found")
    except InvalidToken:
        print("Invalid Password")


#Encrpyting a file
def encrypt_file():
    password = input("Enter password: ").encode('utf-8')
    f_kek, salt = create_kek(password)
    f_dek, data_encryption_key = create_dek()
    encrypted_dek = f_kek.encrypt(data_encryption_key)

    file_path = input("Enter the path to the file you want to encrypt: ")

    try:
        with open(file_path, 'rb' ) as file:
            content = file.read()
            encrypted_data = f_dek.encrypt(content).decode()

        stored_data = {
            "salt": base64.urlsafe_b64encode(salt).decode(),
            "encrypted dek": encrypted_dek.decode(),
            "encrypted data": encrypted_data,
            "file name": file_path
        }

        with open('encryptedfile.enc', 'w') as enc_file:
            json.dump(stored_data, enc_file, indent=4)

        print(f"File '{file_path}' successfully encrypted and saved as 'encryptedfile.enc'.")

    except FileNotFoundError:
        print(f"File {file_path} not found")
    except Exception as e:
        print("Error during encryption:", e)


#Decrypting a file
def decrypt_file():
    try:
        confirm_password = input("Re-Enter password used to encrypt file: ").encode('utf-8')
        try:
            encrypted_file_path = input("Enter path to the encrypted file:")

            with open(encrypted_file_path, 'rb') as enc_file:
                try:
                    stored_data = json.load(enc_file)
                    salt = base64.urlsafe_b64decode(stored_data["salt"])
                    encrypted_dek = stored_data["encrypted dek"]
                    encrypted_data = stored_data["encrypted data"]
                    file_name = stored_data["file name"]

                    f_kek = use_kek(confirm_password, salt)
                    decrypted_dek = f_kek.decrypt(encrypted_dek)
                    f_dek = Fernet(decrypted_dek)
                    decrypted_data = f_dek.decrypt(encrypted_data)
                    decrypted_file = f"decrypted {os.path.basename(file_name)}"

                    with open(decrypted_file, 'wb') as dec_file:
                     dec_file.write(decrypted_data)

                    print(f"File successfully decrypted and saved as '{decrypted_file}'.")
                except InvalidToken:
                    print("Error: Invalid password or corrupted encrypted data.")
                except Exception as e:
                    print("Error during decryption:", e)
        except FileNotFoundError:
            print("Error: Encrypted File not found. Ensure the file exists in the specified location.")
    except InvalidToken:
        print("Invalid Password")

#Main Function to select whether to encrypt or decrypt text or file
def main():
    while True:
        print("\nSelect an action:")
        print("1. Encrypt plaintext")
        print("2. Decrypt plaintext")
        print("3. Encrypt a file")
        print("4. Decrypt a file")
        print("5. Exit")

        try:
            choice = int(input("Enter your choice (1-5): "))
        except ValueError:
            print("Invalid input. Please enter a number between 1 and 5.")
            continue

        if choice == 1:
            print("\nYou selected: Encrypt plaintext")
            enc_text()
        elif choice == 2:
            print("\nYou selected: Decrypt plaintext")
            dec_text()
        elif choice == 3:
            print("\nYou selected: Encrypt a file")
            encrypt_file()
        elif choice == 4:
            print("\nYou selected: Decrypt a file")
            decrypt_file()
        elif choice == 5:
            print("\nExiting the program. Goodbye!")
            break
        else:
            print("Invalid choice. Please select a number between 1 and 5.")


if __name__ == "__main__":
    main()



