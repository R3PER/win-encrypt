# File Encryptor

## 📄 Description
Win Encryptor is a file encryption and decryption program with a graphical interface, written in the Go programming language. The program utilizes advanced cryptographic algorithms (AES) to secure user data.

## ✨ Features
* Encryption of individual files and entire folders
* Decryption of protected files
* Key info recovery system
* User-friendly graphical interface
* Progress indicator for operations
* Protection against debugging and code analysis

## 🖥️ System Requirements
* Windows OS
* Minimum Go version: 1.16

3. Build the program:

    ```bash
    go build -ldflags="-H windowsgui -w -s" -trimpath
    ```

    This command builds the application with Windows optimizations, reducing file size and hiding the console window.

## 🚀 How to Use
1. Launch the program
2. Select a file or folder to encrypt/decrypt
3. Enter a password
4. Choose an operation (encryption/decryption/recovery)
5. Wait for the operation to complete

> ⚠️ Note: The program is under development and may crash unexpectedly. Always create backups of important files before encrypting them.

## 🔧 Potential Improvements

### 🔐 Security
- [ ] Implementation of additional encryption algorithms
- [ ] Addition of a key management system
- [ ] Strengthening protection against brute-force attacks

### 📁 Functionality
- [ ] File compression before encryption
- [ ] Drag-and-drop file encryption/decryption
- [ ] Backup system
- [ ] Support for archive formats (ZIP, RAR)

### 🎨 Interface
- [ ] Dark mode/Light mode
- [ ] Multilingual support
- [ ] Graphical progress bar instead of text-based
- [ ] Pause/resume operation functionality

### ⚡ Performance
- [ ] Optimization for large file processing
- [ ] Improved memory management
- [ ] Parallel file processing

## ✅ Advantages
* Simple and intuitive interface
* Fast performance on small files
* Secure AES encryption
* Recovery function for lost key info files
* Ability to process multiple files simultaneously
* Built-in protection against debugging

## ❌ Disadvantages
* Windows-only support
* Lack of file compression
* Limited handling of large files
* No backup system
* Basic graphical interface
* No support for other operating systems

## 🔒 Security
* AES encryption
* Secure key generation
* File integrity verification
* Protection against debugging
* Secure data deletion

## 📜 License
GNU License

## 👤 Author
**R3PER**
* GitHub: [https://github.com/R3PER](https://github.com/R3PER)

## 📧 Support
If you encounter any issues or have questions, please create an issue on the GitHub repository.
