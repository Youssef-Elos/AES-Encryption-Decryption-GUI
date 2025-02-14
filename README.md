# File Encryption/Decryption Application Using AES
![alt text](https://github.com/Youssef-Elos/AES-Encryption-Decryption-GUI/blob/main/v2.PNG?raw=true)
## Description
This project is a Python-based application that provides AES (Advanced Encryption Standard) encryption and decryption for files. The application offers a user-friendly graphical user interface (GUI) built with Tkinter, enabling users to easily encrypt and decrypt files. The AES algorithm ensures secure encryption, protecting sensitive data with 128-bit keys.

## Features
- **AES File Encryption**: Securely encrypt files using a provided or randomly generated AES key.
- **AES File Decryption**: Decrypt previously encrypted files using the corresponding AES key.
- **Key Generation**: Automatically generate a random 16-byte AES key for encryption.
- **File Handling**: Choose files from the system to encrypt or decrypt through the GUI.
- **User-Friendly Interface**: A simple and intuitive interface that makes encryption and decryption operations easy to perform.

## Installation
To run this application, ensure Python is installed on your system. Clone this repository and install the required packages:

```bash
pip install -r requirements.txt
```

## Usage
1. Clone the repository:
```bash
git clone https://github.com/Ressal0/AES-file-Encryption-Decryption.git
cd AES-file-Encryption-Decryption
```
2. Run the application:
```bash
python aes-file-encryption2.0v.py
```
3. Use the GUI to:
   - Select a file for encryption or decryption.
   - Generate an AES key or use a provided key.
   - Encrypt the selected file or decrypt it back to its original form.

## Files
- `aes-file-encryption2.0v.py`: Contains the AES encryption and decryption functionality, including key generation. And it Manages the graphical user interface and user interactions.
- `requirements.txt`: Lists all required dependencies to run the project.

## Dependencies
- `tkinter`: Used for the graphical interface.
- `os`: For file and key management.
- `pycryptodome`: Provides cryptographic functions, including AES (install via `pip install pycryptodome`).

## Acknowledgements
This project was developed as part of a cybersecurity assignment focused on encryption and decryption methods using Python.

## Contact
For any questions or suggestions, feel free to contact me
