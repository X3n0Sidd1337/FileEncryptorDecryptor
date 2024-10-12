# FileEncryptorDecryptor

**FileEncryptorDecryptor** is a Java-based GUI application that encrypts and decrypts files using AES encryption (CBC mode with PKCS5 padding). It allows users to input an encryption key and initialization vector (IV) in hexadecimal format, select a file to encrypt or decrypt, and generates a `.params` file containing the encryption parameters.

## Features

- **File Encryption**: Encrypts any file using AES/CBC/PKCS5Padding and saves the result with a `.sidenc` extension.
- **File Decryption**: Decrypts `.sidenc` files back to their original format.
- **Key and IV Storage**: Saves the encryption key and IV in a `.params` file, located in the same directory as the encrypted file.
- **Standalone GUI**: Provides an easy-to-use GUI interface for selecting files and inputting the necessary encryption parameters.

## How it works

1. **File Selection**: Users can select any file to encrypt or decrypt.
2. **Key and IV Input**: Users provide a key and IV in hexadecimal format.
   - The AES key must be 128, 192, or 256 bits (16, 24, or 32 bytes).
   - The IV must be 128 bits (16 bytes).
3. **Encryption**: When encrypted, the file is saved with the `.sidenc` extension, and a `.params` file containing the key and IV is generated in the same directory.
4. **Decryption**: Encrypted files with a `.sidenc` extension can be decrypted using the same key and IV.

### Example
- **Original file**: `document.txt`
- **Encrypted file**: `document.txt.sidenc`
- **Parameter file**: `document.params` (contains key and IV)
- **Decrypted file**: `document.txt`

## Installation and Usage

### Requirements
- Java Development Kit (JDK) 8 or higher.

### Compiling the Project
1. Clone the repository:
   ```bash
   git clone https://github.com/X3n0Sidd1337/FileEncryptorDecryptor.git
   cd FileEncryptorDecryptor
   ```
2. Compile the Java files:
   ```bash
   javac FileEncryptorDecryptor.java
   ```
3. Package the compiled classes into a JAR file:
   ```bash
   jar cfe FileEncryptorDecryptor.jar FileEncryptorDecryptor FileEncryptorDecryptor*.class
   ```
### Running the Application
  ```bash
  java -jar FileEncryptorDecryptor.jar
  ```
or simply double-click on FileEncryptorDecryptor.jar
